"""Deterministic synthetic specimens; no credential-shaped values stored in Git.

Recipes retain the original fixed seeds, draw counts and expected SHA-256 values.
Generated values have never been issued by a provider and are never sent to one.
This is test tooling only, not part of the installed detection engine.
"""
import hashlib,json,random,re,string
from pathlib import Path
try:
    from re import _parser as parser,_constants as C
except ImportError:  # Python 3.10 test tooling
    import sre_parse as parser
    import sre_constants as C

ROOT=Path(__file__).resolve().parents[1]

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
    result='';alphabet=string.ascii_letters+string.digits+'_-./+='
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

def recipe_case(rule,positive):
    tree=group_tree(parser.parse(rule['pattern'],re.ASCII|re.MULTILINE),rule['group'])
    rng=random.Random('lhx-catalog-v1:'+rule['upstream_id']+':'+positive['split'])
    for draw in range(40):
        value=specimen(tree,rng)
        if value==positive['secret']:
            before,separator,after=positive['content'].partition(value)
            if not separator:raise ValueError('Missing synthetic value')
            return {'rule':rule['id'],'split':positive['split'],'draw':draw,'before':before,'after':after,
                    'secret_sha256':hashlib.sha256(value.encode()).hexdigest(),
                    'content_sha256':hashlib.sha256(positive['content'].encode()).hexdigest()}
    raise ValueError('Synthetic seed changed')

def cases():
    recipes=json.loads((ROOT/'benchmarks/catalog-cases.json').read_text())
    rules={r['id']:r for r in json.loads((ROOT/'src/agent/js/catalog.json').read_text())['rules']}
    result=[]
    for recipe in recipes['cases']:
        rule=rules[recipe['rule']]
        assert recipe['split'] in ('regression','challenge') and type(recipe['draw']) is int and 0<=recipe['draw']<40
        rng=random.Random('lhx-catalog-v1:'+rule['upstream_id']+':'+recipe['split'])
        tree=group_tree(parser.parse(rule['pattern'],re.ASCII|re.MULTILINE),rule['group'])
        for _ in range(recipe['draw']+1):value=specimen(tree,rng)
        content=recipe['before']+value+recipe['after']
        assert hashlib.sha256(value.encode()).hexdigest()==recipe['secret_sha256'],'Synthetic value changed'
        assert hashlib.sha256(content.encode()).hexdigest()==recipe['content_sha256'],'Synthetic context changed'
        result.append({'rule':recipe['rule'],'split':recipe['split'],'content':content,'secret':value})
    return result
