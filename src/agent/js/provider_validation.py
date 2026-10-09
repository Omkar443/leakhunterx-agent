"""Optional, bounded read-only credential verification on the local machine.

Off by default. Only the provider's fixed HTTPS endpoint receives the candidate;
no credential is sent to LeakHunterX or AI. No account data is downloaded.
"""
import httpx


async def verify_github(value, enabled=False):
    if not enabled: return {'provider':'github','status':'not_attempted'}
    if not value.startswith(('ghp_','gho_','ghu_','ghs_','ghr_','github_pat_')):
        return {'provider':'github','status':'unsupported'}
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False) as client:
            async with client.stream('GET','https://api.github.com/user', headers={
                'Authorization':'Bearer '+value,'Accept':'application/vnd.github+json',
                'X-GitHub-Api-Version':'2022-11-28','User-Agent':'LeakHunterX-verifier/1'}) as response:
                status = 'authenticated' if response.status_code==200 else 'rejected' if response.status_code==401 else 'unknown'
                return {'provider':'github','status':status}
    except (httpx.HTTPError, ValueError):
        return {'provider':'github','status':'unavailable'}
