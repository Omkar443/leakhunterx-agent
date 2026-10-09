"""Target, scope and bounded HTTP contracts shared by scanning stages."""
import ipaddress
import re
import socket
from contextlib import asynccontextmanager
from urllib.parse import urlsplit, urlunsplit, urljoin
import aiohttp


class PipelineError(RuntimeError):
    """Required scan work could not be completed accurately."""


def normalize_target(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError('Invalid target')
    value = value.strip()
    if re.search(r'[\x00-\x20\x7f\\]', value):
        raise ValueError('Invalid target characters')
    parsed = urlsplit(value if '://' in value else 'https://' + value)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Only HTTP and HTTPS targets are supported')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('Credentials cannot be embedded in targets')
    host = parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()
    if not host or '%' in host:
        raise ValueError('Invalid target host')
    try:
        address = ipaddress.ip_address(host)
        authority = '[' + host + ']' if address.version == 6 else host
    except ValueError:
        if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Invalid target host')
        authority = host
    port = parsed.port  # Invalid or out-of-range ports must fail validation.
    if port is not None:
        authority += ':' + str(port)
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or '/', parsed.query, ''))


def is_js_url(value):
    return urlsplit(value).path.lower().endswith(('.js', '.mjs', '.cjs'))


def display_url(value):
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))


def check_address(host, allow_private=False):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if ':' in host or '%' in host:
            raise PipelineError('Invalid resolved network address')
        if host.lower() == 'localhost' and not allow_private:
            raise PipelineError('Private targets require ALLOW_PRIVATE_TARGETS=true')
        return
    if not address.is_global and not allow_private:
        raise PipelineError('Private targets require ALLOW_PRIVATE_TARGETS=true')
    # Cloud metadata and link-local services are never scanning targets.
    if address.is_link_local or address.is_unspecified or address.is_multicast:
        raise PipelineError('Special network addresses are not scanning targets')


class ScanResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, allow_private=False):
        self.allow_private = allow_private
        self.resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        records = await self.resolver.resolve(host, port, family)
        for record in records:
            check_address(record['host'], self.allow_private)
        return records

    async def close(self):
        await self.resolver.close()


@asynccontextmanager
async def guarded_get(session, url, *, in_scope=None, allow_private=False, **kwargs):
    """Validate each redirect BEFORE sending; aiohttp automatic redirects are disabled."""
    current = normalize_target(url)
    kwargs.pop('allow_redirects', None)
    kwargs.pop('max_redirects', None)
    response = None
    try:
        for hop in range(6):
            if in_scope is not None and not in_scope(current):
                raise PipelineError('Request or redirect is outside scan scope')
            check_address(urlsplit(current).hostname, allow_private)
            response = await session.get(current, allow_redirects=False, **kwargs)
            if response.status not in (301, 302, 303, 307, 308):
                yield response
                return
            location = response.headers.get('Location')
            response.release()
            response = None
            if not location or hop == 5:
                raise PipelineError('Invalid or excessive redirects')
            destination = normalize_target(urljoin(current, location))
            if urlsplit(current).scheme == 'https' and urlsplit(destination).scheme != 'https':
                raise PipelineError('TLS downgrade redirect refused')
            current = destination
    finally:
        if response is not None:
            response.release()


async def bounded_text(response, limit=5 * 1024 * 1024):
    length = response.headers.get('Content-Length')
    if length is not None and int(length) > limit:
        raise PipelineError('Response exceeds the scan size limit')
    content = bytearray()
    async for chunk in response.content.iter_chunked(65536):
        if len(content) + len(chunk) > limit:
            raise PipelineError('Response exceeds the scan size limit')
        content.extend(chunk)
    try:
        return content.decode(response.charset or 'utf-8', errors='replace')
    except LookupError:
        return content.decode('utf-8', errors='replace')
