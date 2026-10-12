"""Bounded static recovery. Never execute JS or invent original source names."""
import base64
import json
import re
from urllib.parse import urljoin
from agent.history.contracts import MAX_BYTES

MAX_SOURCES=100
BASE64='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def mapped_location(text,name,body,line,column):
    """Bounded reverse mapping to a declared segment, in UTF-16 columns.

    A nearest segment is labelled as such; it is never an exact token position.
    Maps are untrusted declarations, not proof that a build used this source.
    """
    root=json.loads(text);best=None;segments=0
    def vlq(segment):
        result=[];number=shift=0
        for character in segment:
            digit=BASE64.find(character)
            if digit<0 or shift>30: raise ValueError('Invalid VLQ')
            number|=(digit&31)<<shift
            if digit&32: shift+=5;continue
            result.append(-(number>>1) if number&1 else number>>1);number=shift=0
        if shift: raise ValueError('Incomplete VLQ')
        return result
    def visit(mapping,offset_line=0,offset_column=0,depth=0):
        nonlocal best,segments
        if depth>4: raise ValueError('Indexed map depth')
        if 'sections' in mapping:
            for section in mapping['sections']:
                offset=section['offset'];visit(section['map'],offset_line+offset['line'],(offset_column if offset['line']==0 else 0)+offset['column'],depth+1)
            return
        sources=mapping.get('sources',[]);contents=mapping.get('sourcesContent',[])
        indices={i for i,s in enumerate(sources) if s==name and i<len(contents) and contents[i]==body}
        if not indices:return
        source=original_line=original_column=name_index=0
        for generated_line,encoded in enumerate(mapping.get('mappings','').split(';')):
            generated_column=0
            for segment in encoded.split(','):
                if not segment:continue
                segments+=1
                if segments>100000: raise ValueError('Mapping segment budget')
                values=vlq(segment)
                if len(values) not in (1,4,5):raise ValueError('Invalid mapping segment')
                generated_column+=values[0]
                if generated_column<0:raise ValueError('Negative generated column')
                if len(values)==1:continue
                source+=values[1];original_line+=values[2];original_column+=values[3]
                if source<0 or source>=len(sources) or min(original_line,original_column)<0:raise ValueError('Invalid original position')
                if len(values)==5:
                    name_index+=values[4]
                    if name_index<0 or name_index>=len(mapping.get('names',[])):raise ValueError('Invalid symbol index')
                if source in indices and original_line==line-1 and original_column<=column:
                    distance=column-original_column
                    if best is None or distance<best[0]:
                        best=(distance,{'original_line':line,'original_column_utf16':column,'generated_line':offset_line+generated_line+1,
                            'generated_column_utf16':generated_column+(offset_column if generated_line==0 else 0),
                            'accuracy':'exact_segment' if distance==0 else 'nearest_segment'})
    visit(root)
    return best[1] if best else None


def source_map_reference(content,original):
    # Only a sourceMappingURL comment is a declared relationship.
    tokens=re.finditer(r'"(?:[^"\\]|\\.)*"|\x27(?:[^\x27\\]|\\.)*\x27|`(?:[^`\\]|\\.)*`|//[^\n]*|/\*[\s\S]*?\*/',content)
    matches=[]
    for token in tokens:
        if not token.group().startswith(('//','/*')):continue
        directive=re.fullmatch(r'(?://[#@]\s*sourceMappingURL=([^\s]+)\s*|/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/)',token.group())
        if directive:matches.append(directive)
    if not matches: return None
    raw=next(v for v in matches[-1].groups() if v)
    if raw.startswith('data:'):
        if len(raw)>MAX_BYTES*2: raise ValueError('Map too large')
        header,body=raw.split(',',1)
        if header not in ('data:application/json;base64','data:application/json;charset=utf-8;base64'): raise ValueError('Unsupported inline map')
        decoded=base64.b64decode(body,validate=True)
        if len(decoded)>MAX_BYTES: raise ValueError('Map too large')
        return decoded.decode('utf-8').strip()
    return urljoin(original,raw)


def recover_sources(text):
    """Recover sourcesContent only; sourceRoot never causes network/file access."""
    if len(text.encode())>MAX_BYTES: raise ValueError('Map too large')
    root=json.loads(text,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    recovered=[];total=0
    def visit(mapping,depth=0):
        nonlocal total
        if depth>4 or not isinstance(mapping,dict) or mapping.get('version')!=3: raise ValueError('Invalid source map')
        if 'sections' in mapping:
            sections=mapping['sections']
            if not isinstance(sections,list) or len(sections)>MAX_SOURCES: raise ValueError('Invalid indexed map')
            for section in sections:
                if not isinstance(section,dict) or 'url' in section or not isinstance(section.get('offset'),dict): raise ValueError('External indexed maps are not supported')
                for axis in ('line','column'):
                    if type(section['offset'].get(axis)) is not int or section['offset'][axis]<0: raise ValueError('Invalid section offset')
                visit(section.get('map'),depth+1)
            return
        sources,contents=mapping.get('sources'),mapping.get('sourcesContent')
        if not isinstance(sources,list) or len(sources)>MAX_SOURCES or any(s is not None and (not isinstance(s,str) or len(s)>1024) for s in sources): raise ValueError('Invalid source list')
        if contents is None: return
        if not isinstance(contents,list) or len(contents)!=len(sources): raise ValueError('Invalid embedded content')
        # Mapping data is retained as provenance only. Recovered source findings
        # use their actual source line; no unverified generated location is claimed.
        if not isinstance(mapping.get('mappings',''),str) or len(mapping.get('mappings',''))>MAX_BYTES: raise ValueError('Invalid mapping data')
        for name,body in zip(sources,contents):
            if body is None: continue
            if not isinstance(body,str): raise ValueError('Invalid source content')
            total+=len(body.encode())
            if total>MAX_BYTES or len(recovered)>=MAX_SOURCES: raise ValueError('Recovered source limit')
            recovered.append((name or 'unknown',body))
    visit(root)
    return recovered


def literal_assignments(content):
    """Conservative JSON-string concatenation recovery; not a JS interpreter.

    Only double-quoted JSON-compatible literals assigned to a named variable are
    supported. Strings in comments and templates are not reconstructed.
    """
    token=r'"(?:[^"\\\r\n]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"'
    pattern=re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,100})\s*=\s*('+token+r'(?:\s*\+\s*'+token+r'){1,15})\s*[;,]')
    # Remove comments and quoted strings from the search mask while retaining
    # offsets. The assignment prefix must be code, not string/comment content.
    mask=list(content)
    for match in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:[^"\\]|\\.)*"|\x27(?:[^\x27\\]|\\.)*\x27|`(?:[^`\\]|\\.)*`',content):
        mask[match.start():match.end()]=' '*(match.end()-match.start())
    masked=''.join(mask)
    for index,match in enumerate(pattern.finditer(content)):
        if index>=200: break
        if not masked[match.start():match.start()+3].strip(): continue
        try: joined=''.join(json.loads(v.group()) for v in re.finditer(token,match.group(2)))
        except (ValueError,TypeError): continue
        if len(joined)>8192: continue
        yield match.group(1)+' = '+json.dumps(joined)+';',content.count('\n',0,match.start())+1
