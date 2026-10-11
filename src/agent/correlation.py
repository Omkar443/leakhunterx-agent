"""Workspace-scoped identity computed before sanitization; no source upload."""
import base64
import hashlib
import hmac
import json
import re


def approved(value):
    if not isinstance(value,dict) or set(value)!={'version','key_id','key'} or value['version']!=1: return None
    try:
        key=base64.b64decode(value['key'],altchars=b'-_',validate=True)
        if len(key)!=32 or hashlib.sha256(key).hexdigest()[:32]!=value['key_id']: return None
        return value
    except (ValueError,TypeError): return None


def normalized_secret(detector,secret):
    # Provider tokens and JWTs are case-sensitive. Normalize only syntax-neutral
    # whitespace and PEM newlines; never a token's internal bytes.
    value=str(secret).strip()
    if len(value)>=2 and value[0]==value[-1] and value[0] in ('"',"'",'`'): value=value[1:-1]
    if 'private' in detector.lower() and 'key' in detector.lower(): value=value.replace('\r\n','\n').replace('\r','\n')
    return value


def fields(config,detector,secret):
    config=approved(config)
    if not config: return {}
    rule=re.sub('[^a-z0-9_]','_',detector.lower().replace(' ','_'))
    message=json.dumps(['secret-correlation-v1',rule,normalized_secret(rule,secret)],separators=(',',':'),ensure_ascii=True).encode()
    token=hmac.new(base64.urlsafe_b64decode(config['key']),message,hashlib.sha256).hexdigest()
    return {'correlation_fingerprint':token,'correlation_key_id':config['key_id'],'correlation_version':1}
