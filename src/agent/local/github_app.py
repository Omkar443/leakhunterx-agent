"""Consume a web-authorized assignment. Temporary tokens never enter checkpoints."""
import asyncio
from datetime import datetime, timezone
import re
from uuid import UUID
import httpx
from agent.local.registry import Registry, PROFILES
from agent.sources.github import repository_url, private_directory, git_command
import secrets


def register_assignment(registry, assignment):
    info=assignment.get('github_app')
    if not isinstance(info,dict) or set(info)!={'repository_url','repository_id','project_id'}: raise ValueError('Invalid GitHub App assignment')
    identifier=str(UUID(assignment['target_id']));project=str(UUID(info['project_id']))
    url=repository_url(info['repository_url'])
    if (url!=info['repository_url'] or assignment.get('source_type')!='GITHUB' or assignment.get('target')!='github://'+identifier
            or type(info['repository_id']) is not int or not 0<info['repository_id']<2**63
            or assignment.get('profile') not in PROFILES or type(assignment.get('config_version')) is not int
            or assignment['config_version']<1): raise ValueError('Invalid GitHub App scope')
    with registry.connect() as db:
        row=db.execute('SELECT * FROM targets WHERE id=?',(identifier,)).fetchone()
        if row:
            if (not row['app_managed'] or not row['dashboard_allowed'] or row['source_type']!='GITHUB' or row['project_id']!=project
                    or assignment['config_version']<row['config_version']
                    or (row['repository_url']!=url and assignment['config_version']<=row['config_version'])):
                raise ValueError('GitHub App target scope changed')
            db.execute('UPDATE targets SET dashboard_allowed=1,profile=?,config_version=?,repository_url=? WHERE id=?',
                (assignment['profile'],assignment['config_version'],url,identifier))
        else:
            if db.execute('SELECT count(*) FROM targets').fetchone()[0]>=100: raise ValueError('Agent target allowance is full')
            root=private_directory(private_directory(registry.path.parent/'repositories')/identifier)
            db.execute('INSERT INTO targets(id,name,path,project_id,dashboard_allowed,profile,config_version,key,key_id,source_type,repository_url,app_managed) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)',
                (identifier,url.rsplit('/',1)[-1][:80],str(root),project,1,assignment['profile'],assignment['config_version'],
                 secrets.token_bytes(32),str(UUID(bytes=secrets.token_bytes(16))),'GITHUB',url))
    return registry.get(identifier)


class TemporaryGitAccess:
    def __init__(self, token, expires):
        self.token=token;self.expires=expires

    def __call__(self, root, args, **kwargs):
        if kwargs.get('network') and (not self.token or datetime.now(timezone.utc)>=self.expires):
            raise RuntimeError('Temporary GitHub authorization expired; resume this scan')
        return git_command(root,args,credential=self.token,use_local_credential=False,**kwargs)

    def clear(self): self.token=None


async def prepare_assignment(client, assignment, registry=None):
    registry=registry or Registry()
    # Authorization must arrive before a new registration can be persisted.
    identifier=str(UUID(assignment['scan_id']))
    response=None
    for attempt in range(3):
        try:
            response=await client.post('/api/v1/agent/scans/'+identifier+'/github-access')
            if response.status_code not in (429,502,503,504): break
        except httpx.TransportError:
            if attempt==2: raise RuntimeError('Temporary GitHub access is unavailable') from None
        if attempt<2: await asyncio.sleep(5)
    if response is None or response.status_code!=200: raise RuntimeError('GitHub assignment access refused or unavailable')
    if len(response.content)>12000: raise ValueError('Invalid GitHub access response')
    value=response.json()
    if set(value)!={'token','expires_at','repository_url'} or value['repository_url']!=assignment['github_app']['repository_url']:
        raise ValueError('GitHub access scope mismatch')
    token=value.get('token')
    try:
        expires=datetime.fromisoformat(value['expires_at'].replace('Z','+00:00'))
        lifetime=(expires-datetime.now(timezone.utc)).total_seconds()
        if not isinstance(token,str) or not re.fullmatch(r'ghs_[A-Za-z0-9_]{8,4096}',token) or not 30<lifetime<=3660: raise ValueError()
    except (ValueError,TypeError,KeyError): raise ValueError('Invalid temporary GitHub access') from None
    register_assignment(registry,assignment)
    return TemporaryGitAccess(token,expires)
