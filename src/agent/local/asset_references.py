"""Finite URL metadata only; no query, credentials, source or token paths."""
import re
from urllib.parse import urlsplit,urlunsplit,unquote

URLS=re.compile(r'https?://[^\s\'"<>`\\]{1,512}')
TOKEN=re.compile(r'(?i)(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[\w-]{30,}|(?:gh[pousr]_|github_pat_|sk_(?:live|test)_|xox[baprs]-)[\w-]{10,}|eyJ[\w-]+\.[\w-]+\.[\w-]+|[a-z0-9_+=-]{40,}')


def references(content):
    result={}
    for match in URLS.finditer(content):
        try:
            p=urlsplit(match.group().rstrip(');,}].'))
            if not p.hostname or p.username or p.password or p.port not in (None,80,443): continue
            host=p.hostname.rstrip('.').encode('idna').decode().lower()
            path=p.path or '/'
            if TOKEN.search(unquote(host+path)) or any(c in path for c in ('$','{','}')): continue
            # urlsplit.hostname omits IPv6 brackets; urlunsplit does not add
            # them. Preserve a valid authority for the backend privacy gate.
            authority='['+host+']' if ':' in host else host
            url=urlunsplit((p.scheme,authority,path,'',''))
            if len(url)>512 or any(ord(c)<33 for c in url): continue
            result[url]={'kind':'ENDPOINT','locator':url,'method':'UNKNOWN'}
            if len(result)>=10: break
        except (ValueError,UnicodeError): continue
    return list(result.values())
