"""Keep the matched expression and nearby usage within a strict context budget."""
import re


def redact_neighbors(text):
    # Known provider tokens and quoted credential assignments, including nearby matches.
    text = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIzaSy[\w-]{20,}|\b(?:gh[pousr]_|sk_(?:live|test)_|xox[baprs]-)[\w-]{12,}|\beyJ[\w-]+\.[\w-]+\.[\w-]+', '[NEIGHBOR_CREDENTIAL_REDACTED]', text)
    return re.sub(r'''(?i)((?:["']?(?:api[_-]?key|access[_-]?token|secret[_-]?key|password|authorization)["']?)\s*[:=]\s*)(["'])([^"'\n]{8,})\2''',
        lambda m: m.group(0) if '[REDACTED' in m[3] or 'REDACTED]' in m[3] else m[1] + m[2] + '[NEIGHBOR_CREDENTIAL_REDACTED]' + m[2], text)


def centered_context(lines, target, redact, before=30, after=30, limit=3000):
    limit = max(128, limit)
    start, end = max(0, target-before), min(len(lines), target+after+1)
    match = redact(lines[target])
    truncated = False
    # Crop AFTER redaction so neither half of a credential can survive the crop.
    if len(match) > limit-70:
        marker = match.find('[REDACTED')
        if marker < 0:
            marker = match.find('REDACTED')
        pos = max(0, marker)
        offset = max(0, pos-(limit-70)//2)
        match = '…' + match[offset:offset+limit-70] + '…'
        truncated = True
    selected = {target: f'{target+1:4d} | {match}  <-- [MATCH]'}
    used = len(selected[target])
    # Nearest lines first; stop each direction at the first oversized line.
    stopped = set()
    for distance in range(1, max(before, after)+1):
        for direction in (-1, 1):
            idx = target+distance*direction
            if direction in stopped or idx < start or idx >= end:
                continue
            line = f'{idx+1:4d} | {redact(lines[idx])}'
            if used+len(line)+1 <= limit:
                selected[idx] = line
                used += len(line)+1
            else:
                stopped.add(direction)
                truncated = True
    indices = sorted(selected)
    return {'code_context': '\n'.join(selected[i] for i in indices),
        'context_start_line': indices[0]+1, 'context_end_line': indices[-1]+1,
        'line_number': target+1, 'is_truncated': truncated}
