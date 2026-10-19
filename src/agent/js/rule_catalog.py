"""Immutable offline rule catalog and bounded, keyword-indexed candidate matching."""
import hashlib,json,math,re,time
from collections import Counter
from functools import lru_cache
from importlib.resources import files
import regex
import ahocorasick
from .detection_policy import placeholder

CATALOG_VERSION='catalog-500-v1'
PUBLIC_ROLE=re.compile(r'(?i)(?:public|publishable|client[_-]?id|account[_-]?id|checksum|hash|digest|fingerprint|nonce|etag|integrity)')
ASSIGNMENT=re.compile(r'''([A-Za-z_$][\w$.-]{0,120})["']?\s*(?:=>|:=|=|:)\s*["'`]?\s*$''')
CREDENTIAL_ROLE=re.compile(r'(?i)(?:secret|token|password|passwd|private|api[_-]?key|access[_-]?key|credential|auth|(?:^|[_-])key$)')

def acceptable(rule,value,entropy,source,match):
    if not 12<=len(value)<=1024 or placeholder(value) or entropy<rule['min_entropy']:return False
    requirements=rule['requirements']
    for key,characters in (('min_digits',str.isdigit),('min_uppercase',str.isupper),('min_lowercase',str.islower)):
        if sum(characters(c) for c in value)<requirements.get(key,0):return False
    specials=requirements.get('special_chars','!@#$%^&*()')
    if sum(c in specials for c in value)<requirements.get('min_special_chars',0):return False
    if any(word.lower() in value.lower() for word in requirements.get('ignore_if_contains',[])):return False
    start,end=match.span(rule['group'])
    # Never accept a regex prefix of a longer opaque credential/hash.
    if end<len(source) and value[-1].isalnum() and source[end] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-':return False
    if start and value[0].isalnum() and source[start-1] in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_':return False
    assignment=ASSIGNMENT.search(source[max(0,start-256):start])
    if assignment and PUBLIC_ROLE.search(assignment[1]):return False
    if rule['mode']=='context':
        if not assignment or not CREDENTIAL_ROLE.search(assignment[1]):return False
    return True

@lru_cache(maxsize=1)
def load_catalog():
    raw=files('agent.js').joinpath('catalog.json').read_bytes()
    from .catalog_manifest import CATALOG_SHA256
    if hashlib.sha256(raw).hexdigest()!=CATALOG_SHA256:raise RuntimeError('Detector catalog integrity check failed')
    data=json.loads(raw)
    if data.get('version')!=CATALOG_VERSION or len(data.get('rules',[]))!=462:raise RuntimeError('Detector catalog invalid')
    ids=set();patterns=set();rows=[]
    required={'id','name','pattern','group','keyword','mode','min_entropy','requirements','severity','confidence','references','upstream_id','source_path'}
    for item in data['rules']:
        if not isinstance(item,dict) or set(item)!=required or not re.fullmatch('[a-z0-9][a-z0-9_]{2,119}',item['id']) or item['id'] in ids or item['pattern'] in patterns:raise RuntimeError('Detector catalog identity invalid')
        if not isinstance(item['pattern'],str) or len(item['pattern'])>8192 or not isinstance(item['keyword'],str) or not 3<=len(item['keyword'])<=128 or item['mode'] not in ('format','context'):raise RuntimeError('Detector catalog pattern invalid')
        if item['group']!=1 or item['severity'] not in ('high','medium') or type(item['min_entropy']) not in (float,int) or not 0<=item['min_entropy']<=8 or not 0<item['confidence']<1:raise RuntimeError('Detector catalog policy invalid')
        compiled=regex.compile(item['pattern'],regex.ASCII|regex.MULTILINE|regex.VERSION0)
        if compiled.groups!=1:raise RuntimeError('Detector capture invalid')
        ids.add(item['id']);patterns.add(item['pattern']);rows.append((item,compiled))
    return tuple(rows),hashlib.sha256(raw).hexdigest()

class CatalogMatcher:
    def __init__(self):
        self.rows,self.digest=load_catalog()
        self.by_keyword={}
        for row,compiled in self.rows:self.by_keyword.setdefault(row['keyword'],[]).append((row,compiled))
        self.triggers=ahocorasick.Automaton()
        for keyword in self.by_keyword:self.triggers.add_word(keyword,keyword)
        self.triggers.make_automaton()

    def candidates(self,source):
        # A single scan selects relevant rules. Full regexes keep exact upstream
        # context across line/chunk boundaries; they never scan guessed windows.
        selected=set()
        seen=set();trigger_deadline=time.monotonic()+2
        for count,(_,keyword) in enumerate(self.triggers.iter(source.lower())):
            if count%1024==0 and time.monotonic()>trigger_deadline:raise RuntimeError('Detector keyword budget exceeded')
            if keyword not in seen:
                seen.add(keyword);selected.update(row['id'] for row,_ in self.by_keyword[keyword])
        deadline=time.monotonic()+2
        for row,compiled in self.rows:
            if row['id'] not in selected:continue
            remaining=deadline-time.monotonic()
            if remaining<=0:raise RuntimeError('Detector catalog budget exceeded')
            try:
                for match in compiled.finditer(source,timeout=min(.10,remaining)):
                    value=match.group(row['group'])
                    if not value:continue
                    sample=value[:4096];counts=Counter(sample)
                    entropy=-sum((n/len(sample))*math.log2(n/len(sample)) for n in counts.values())
                    if acceptable(row,value,entropy,source,match):yield row,match
            except TimeoutError:raise RuntimeError('Detector rule budget exceeded: '+row['id']) from None

@lru_cache(maxsize=1)
def matcher():return CatalogMatcher()
