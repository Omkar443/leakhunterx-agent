import hashlib
import ipaddress
import json
import re
from datetime import date, datetime
from urllib.parse import urlsplit,urlunsplit,parse_qsl,unquote

MAX_BYTES=3_000_000
MAX_SCAN_BYTES=100_000_000
MAX_INDEX_BYTES=2_000_000


def url(value):
    if not isinstance(value,str) or len(value)>2048 or any(ord(c)<33 or ord(c)==127 for c in value): raise ValueError('Invalid archive URL')
    p=urlsplit(value)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.fragment or p.port not in (None,443 if p.scheme=='https' else 80): raise ValueError('Invalid archive URL')
    if any(k not in ('v','ver','version','build','cache','t','_','hash') or not re.fullmatch('[A-Za-z0-9._-]{1,64}',v) for k,v in parse_qsl(p.query,keep_blank_values=True)):raise ValueError('Unsupported query parameters')
    if re.search(r'(?:gh[pousr]_[A-Za-z0-9_.-]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{30,}|AKIA[A-Z0-9]{16}|gsk_[A-Za-z0-9]{20,})',unquote(p.path+'?'+p.query)):raise ValueError('Credential-bearing locator')
    host=p.hostname.rstrip('.').encode('idna').decode().lower()
    try: ipaddress.ip_address(host)
    except ValueError: pass
    else: raise ValueError('Domain required')
    if '.' not in host or host.endswith(('.local','.localhost','.internal','.invalid','.test')): raise ValueError('Public domain required')
    return urlunsplit((p.scheme,host,p.path or '/',p.query,''))


def validate(target,config):
    target=url(target)
    if urlsplit(target).path!='/' or urlsplit(target).query: raise ValueError('Domain root required')
    if not isinstance(config,dict) or set(config)!={'from_date','to_date','include_subdomains','max_captures','policy_version'}: raise ValueError('Invalid history configuration')
    start,end=date.fromisoformat(config['from_date']),date.fromisoformat(config['to_date'])
    if not date(1996,1,1)<=start<=end<=date.today() or type(config['include_subdomains']) is not bool or type(config['max_captures']) is not int or not 1<=config['max_captures']<=300 or type(config['policy_version']) is not int or config['policy_version']!=1: raise ValueError('Invalid history policy')
    scope=hashlib.sha256(json.dumps({'target':urlsplit(target).hostname,**config},sort_keys=True).encode()).hexdigest()
    return target,scope


def permitted(original,target,config,timestamp):
    try:
        original=url(original);host=urlsplit(original).hostname;root=urlsplit(target).hostname
        capture=datetime.strptime(timestamp,'%Y%m%d%H%M%S').date()
        return (host==root or config['include_subdomains'] and host.endswith('.'+root)) and config['from_date']<=capture.isoformat()<=config['to_date']
    except (ValueError,TypeError): return False
