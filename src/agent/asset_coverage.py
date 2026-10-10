"""Bounded previous-asset rechecks and non-secret per-asset coverage receipts."""
import asyncio
import hashlib
import os
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from .js.detection_policy import POLICY_VERSION
from .utils.events import emit_event
from .utils.pipeline import normalize_target, guarded_get, bounded_text, ScanResolver, PipelineError

MAX_RECHECK_ASSETS = 500


def canonical_asset_url(url):
    parsed = urlsplit(normalize_target(url))
    host = parsed.hostname
    authority = f'[{host}]' if ':' in host else host
    if parsed.port and parsed.port != (443 if parsed.scheme == 'https' else 80): authority += f':{parsed.port}'
    return urlunsplit((parsed.scheme, authority, parsed.path, parsed.query, ''))


def asset_id(url):
    return hashlib.sha256(canonical_asset_url(url).encode()).hexdigest()


def detector_policy(context, aggressive=None):
    from .js.ignore_policy import IgnorePolicy
    policy = context.shared_state.get('ignore_policy')
    if policy is None:
        policy = IgnorePolicy.load(context.config.get('ignore_file') or os.environ.get('LHX_IGNORE_FILE', '.lhxignore'))
        context.shared_state['ignore_policy'] = policy
    if aggressive is None:
        aggressive = context.config.get('aggressive_secrets', True)
    acquisition = context.shared_state.get('acquisition_policy')
    suffix = f':{acquisition}' if acquisition else ''
    return hashlib.sha256(f'{POLICY_VERSION}:{bool(aggressive)}:{policy.digest}{suffix}'.encode()).hexdigest()


def challenge_response(content):
    folded = content[:65536].lower()
    return any(marker in folded for marker in ('cf-chl-', 'g-recaptcha', 'type="password"', "type='password'"))


async def observe(context, url, kind, outcome, content_hash=None, aggressive=None):
    canonical = canonical_asset_url(url)
    payload = {'asset_url': canonical, 'asset_id': asset_id(canonical), 'kind': kind,
               'outcome': outcome, 'detector_policy': detector_policy(context, aggressive)}
    if content_hash: payload['content_sha256'] = content_hash
    await emit_event(context, event_type='asset_observation', data=payload)
    context.shared_state.setdefault('observed_assets', {})[payload['asset_id']] = outcome


def validated_rechecks(manifest, scope_check):
    if not isinstance(manifest, dict) or not isinstance(manifest.get('assets'), list): return []
    unique = {}
    for entry in manifest['assets'][:MAX_RECHECK_ASSETS]:
        if not isinstance(entry, dict) or entry.get('kind') not in ('javascript', 'document'): continue
        try:
            url = canonical_asset_url(entry.get('url'))
        except (ValueError, TypeError): continue
        if scope_check(url): unique[url] = entry['kind']
    return [{'url': url, 'kind': kind} for url, kind in unique.items()]


async def recheck_documents(context, assets):
    """Optional checks have their own budget; delivery failure stays fatal."""
    from .js.leak_detector import SecretScanner
    from .events.outbox import DeliveryPending
    pending = [item for item in assets if item['kind'] == 'document'
               and context.shared_state.get('observed_assets', {}).get(asset_id(item['url'])) != 'analyzed']
    if not pending: return
    semaphore = asyncio.Semaphore(3)
    connector = aiohttp.TCPConnector(limit=3, ssl=context.config.get('verify_ssl', True),
                                     resolver=ScanResolver(context.config.get('allow_private_targets', False)))
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=15)) as session:
        async def check(item):
            async with semaphore:
                if await context.check_pause_stop(): return
                url = item['url']
                try:
                    async with guarded_get(session, url, in_scope=context.domain_manager.is_in_scope,
                                           allow_private=context.config.get('allow_private_targets', False)) as response:
                        if response.status != 200:
                            await observe(context, url, 'document', 'unavailable', aggressive=False); return
                        if canonical_asset_url(str(response.url)) != url:
                            await observe(context, url, 'document', 'redirected', aggressive=False); return
                        content = await bounded_text(response, 2 * 1024 * 1024)
                        # HTML challenge/login responses must not prove removal.
                        if not content or challenge_response(content):
                            await observe(context, url, 'document', 'unavailable', aggressive=False); return
                        await SecretScanner().scan(content, url, context)
                        await observe(context, url, 'document', 'analyzed', hashlib.sha256(content.encode()).hexdigest(), aggressive=False)
                except DeliveryPending:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, PipelineError):
                    await observe(context, url, 'document', 'unavailable', aggressive=False)
        tasks = [asyncio.create_task(check(item)) for item in pending]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=60)
        except asyncio.TimeoutError:
            # Unattempted checks remain unverified; absence of a receipt is not success.
            pass
        finally:
            for task in tasks:
                if not task.done(): task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
