"""Offline, reproducible adapter for a reviewed pinned Apache-2.0 rule snapshot.

Reads data only from the archive; upstream code, validators and templates never run.
Requires PyYAML and regex in the developer environment, not in production.
"""
import argparse,hashlib,io,json,random,re,string,zipfile
from pathlib import Path
from collections import Counter
import math,sys
from re import _parser as parser,_constants as C
import regex
import yaml

SHA='82d050530cdef9af070b8f9a75701c9c27a948c3'
ZIP_HASH='4608d6df5f44e3905545e001c0406282d00d8af6a9974503ab8a8c338f0efa54'
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from agent.js.rule_catalog import acceptable
CLASSES={'alnum':'A-Za-z0-9','alpha':'A-Za-z','digit':'0-9','xdigit':'A-Fa-f0-9','word':'A-Za-z0-9_','space':r'\s','blank':r' \t','lower':'a-z','upper':'A-Z','ascii':r'\x00-\x7f','punct':r'!-/:-@\[-`{-~'}
SKIP_FAMILIES={'aws','github','gitlab','stripe','twilio','slack','google','gcp','openai','anthropic','sendgrid','npm','discord','jwt','privatekey','private-key','ssh','telegram','mapbox','cloudinary','shopify','facebook','algolia','segment','mixpanel','amplitude','recaptcha','s3','azure','mailgun','huggingface','generic','mongodb','mysql','postgres','redis'}
ADDITIONAL_FORMATS={'kingfisher.aws.bedrock.long_lived','kingfisher.aws.6','kingfisher.azure.2','kingfisher.azure.3','kingfisher.github.9'}|{'kingfisher.gitlab.'+str(n) for n in (2,3,4,5,6,8,9,10,11,12,13,14,15)}

def convert(pattern):
    pattern=re.sub(r'\[:([a-z]+):\]',lambda m:CLASSES[m[1]],pattern)
    return re.sub(r'\(\?<([A-Za-z_][A-Za-z_0-9]*)>',r'(?P<\1>',pattern)

def literals(tree):
    """One literal guaranteed on every path, or none: an optimization, never a guess."""
    choices=[];run=''
    def flush():
        nonlocal run
        if len(run)>=3:choices.append(run)
        run=''
    for op,arg in tree:
        if op==C.LITERAL:run+=chr(arg);continue
        flush()
        if op==C.SUBPATTERN:choices.extend(literals(arg[-1]))
        elif op in (C.MAX_REPEAT,C.MIN_REPEAT) and arg[0]>0:choices.extend(literals(arg[2]))
        elif op==C.BRANCH:
            sets=[set(literals(branch)) for branch in arg[1]]
            if sets:choices.extend(set.intersection(*sets))
    flush()
    return choices

def group_tree(tree,number):
    for op,arg in tree:
        if op==C.SUBPATTERN:
            if arg[0]==number:return arg[-1]
            found=group_tree(arg[-1],number)
            if found is not None:return found
        elif op in (C.MAX_REPEAT,C.MIN_REPEAT):
            found=group_tree(arg[2],number)
            if found is not None:return found
        elif op==C.BRANCH:
            for branch in arg[1]:
                found=group_tree(branch,number)
                if found is not None:return found

def specimen(tree,rng):
    result=''
    alphabet=string.ascii_letters+string.digits+'_-./+='
    for op,arg in tree:
        if op==C.LITERAL:result+=chr(arg)
        elif op==C.SUBPATTERN:result+=specimen(arg[-1],rng)
        elif op in (C.MAX_REPEAT,C.MIN_REPEAT):
            low,high,body=arg
            count=low if low==high else rng.randint(low,min(high,low+6))
            if count>1024:raise ValueError('large repeat')
            result+=''.join(specimen(body,rng) for _ in range(count))
        elif op==C.BRANCH:result+=specimen(rng.choice(arg[1]),rng)
        elif op==C.IN:
            negate=arg[0][0]==C.NEGATE;allowed=set()
            for kind,value in arg:
                if kind==C.LITERAL:allowed.add(chr(value))
                elif kind==C.RANGE:allowed.update(chr(v) for v in range(value[0],min(value[1],126)+1))
                elif kind==C.CATEGORY:
                    allowed.update(string.digits if value==C.CATEGORY_DIGIT else ' \t' if value==C.CATEGORY_SPACE else string.ascii_letters+string.digits+'_')
                elif kind!=C.NEGATE:raise ValueError('unsupported class')
            options=[v for v in alphabet if (v not in allowed if negate else v in allowed)]
            if not options:options=sorted(v for v in allowed if 32<=ord(v)<127)
            if not options:raise ValueError('empty class')
            result+=rng.choice(options)
        elif op==C.ANY:result+=rng.choice(string.ascii_letters+string.digits)
        elif op==C.NOT_LITERAL:result+=rng.choice([v for v in alphabet if ord(v)!=arg])
        elif op==C.CATEGORY:result+=rng.choice(string.digits if arg==C.CATEGORY_DIGIT else string.ascii_letters)
        elif op in (C.AT,C.ASSERT,C.ASSERT_NOT):continue
        else:raise ValueError('unsupported regex operation')
    return result

def main():
    args=argparse.ArgumentParser();args.add_argument('source_zip',type=Path);args=args.parse_args()
    data=args.source_zip.read_bytes()
    if hashlib.sha256(data).hexdigest()!=ZIP_HASH:raise ValueError('Source archive hash mismatch')
    archive=zipfile.ZipFile(io.BytesIO(data));candidates=[];excluded=Counter()
    for path in sorted(archive.namelist()):
        if '/data/rules/' not in path or not path.endswith(('.yaml','.yml')):continue
        for rule in yaml.safe_load(archive.read(path)).get('rules',[]):
            identifier=rule['id'];family=identifier.split('.')[1]
            if (family in SKIP_FAMILIES and identifier not in ADDITIONAL_FORMATS) or rule.get('visible') is False or rule.get('depends_on_rule') or rule.get('confidence') not in ('high','medium') or not rule.get('references') or 'checksum' in rule.get('pattern_requirements',{}):excluded['scope_or_semantics']+=1;continue
            if re.search(r'(?i)\b(?:public|publishable|client id|account id|organization id|tenant id|app id)\b',rule['name']):excluded['public_identifier']+=1;continue
            try:
                pattern=convert(rule['pattern']);compiled=regex.compile(pattern,regex.ASCII|regex.MULTILINE|regex.VERSION0)
                tree=parser.parse(pattern,re.ASCII|re.MULTILINE)
                number=compiled.groupindex.get('TOKEN',1)
                if compiled.groups!=1:raise ValueError('multi-component rule')
                capture_tree=group_tree(tree,number)
                if capture_tree is None:raise ValueError('missing capture')
                words=[s for s in literals(tree) if all(32<=ord(c)<127 for c in s)]
                if not words:raise ValueError('no guaranteed literal')
                # Prefer a provider-specific trigger over generic credential words.
                keyword=max(words,key=lambda s:(s.lower() not in ('secret','token','password','private','apikey','access','key'),len(s)))
                strong=any(re.search('[A-Za-z]{3}',s) for s in literals(capture_tree))
                slug=re.sub('[^a-z0-9]+','_',rule['name'].lower()).strip('_')
                if identifier=='kingfisher.msteams.1':slug='microsoft_teams_legacy_webhook'
                elif identifier=='kingfisher.microsoftteamswebhook.1':slug='microsoft_teams_webhook_b2'
                entry={'id':slug+'_'+identifier.rsplit('.',1)[-1],'name':rule['name'],
                    'pattern':pattern,'group':number,'keyword':keyword.lower(),'mode':'format' if strong else 'context',
                    'min_entropy':max(3.0,float(rule.get('min_entropy',3.0))),
                    'requirements':rule.get('pattern_requirements',{}),'severity':'high' if strong else 'medium','confidence':.85 if strong else .70,
                    'references':rule['references'],'upstream_id':identifier,'source_path':path.split('/',1)[1]}
                positives=[]
                for seed in ('regression','challenge'):
                    rng=random.Random('lhx-catalog-v1:'+identifier+':'+seed)
                    found=None
                    for trial in range(40):
                        token=specimen(capture_tree,rng)
                        if not 12<=len(token)<=1024:continue
                        for example in rule.get('examples',[]):
                            match=compiled.search(example,timeout=.05)
                            if not match:continue
                            start,end=match.span(number);content=example[:start]+token+example[end:]
                            # Fixtures contain new synthetic bytes, never upstream keys.
                            replacement=compiled.search(content,timeout=.05)
                            count=Counter(token);entropy=-sum(n/len(token)*math.log2(n/len(token)) for n in count.values())
                            if replacement and replacement.group(number)==token and keyword.lower() in content.lower() and acceptable(entry,token,entropy,content,replacement):
                                positives.append({'split':seed,'content':content,'secret':token});found=True;break
                        if found:break
                    if not found:raise ValueError('no synthetic specimen')
                candidates.append((entry,positives))
            except (ValueError,KeyError,TypeError,re.error,regex.error,TimeoutError):excluded['unsupported_or_unexercised']+=1
    unique={}
    for entry,positive in candidates:
        identity=re.sub(r'\s+','',entry['pattern'])
        if identity in unique:excluded['duplicate_pattern']+=1;continue
        unique[identity]=(entry,positive)
    rows=list(unique.values())
    print(json.dumps({'eligible':len(rows),'modes':dict(Counter(r['mode'] for r,_ in rows)),'excluded':dict(excluded)}))
    output=ROOT/'tools/catalog-candidates.json';output.write_text(json.dumps({'source_commit':SHA,'source_sha256':ZIP_HASH,'candidates':[{'rule':r,'positives':p} for r,p in rows]},indent=2)+'\n')
    for name in ('LICENSE','NOTICE'):
        source=next((p for p in archive.namelist() if p==f'kingfisher-{SHA}/{name}'),None)
        if source:
            target=ROOT/'docs/third-party';target.mkdir(exist_ok=True);(target/('KINGFISHER-'+name+'.txt')).write_bytes(archive.read(source))
if __name__=='__main__':main()
