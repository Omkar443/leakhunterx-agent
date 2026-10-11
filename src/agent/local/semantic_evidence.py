"""Bounded lexical observations. Only finite categories and counters leave the agent."""
import math
import re
from collections import Counter
from agent.js.detection_policy import placeholder, valid_candidate

WINDOW_RADIUS = 2048


def extract(content, locator, finding):
    secret = str(finding.get('value', ''))
    rule = str(finding['type'])
    start = max(0, int(finding.get('match_start') or 0))
    end = max(start, int(finding.get('match_end') or start + len(secret)))
    position = content.find(secret, start, min(len(content), end + 1)) if secret else -1
    position = start if position < 0 else position
    left, right = max(0, position - WINDOW_RADIUS), min(len(content), position + len(secret) + WINDOW_RADIUS)
    # Large key containers are not copied into the usage window.
    window = content[left:position] + '__lhx_candidate__' + content[position + len(secret):right]
    prefix = content[max(left, position - 256):position]
    assignment = re.search(r'(?:[\x27\x22]?)([A-Za-z_$][\w$.-]{0,100})[\x27\x22]?\s*[:=]\s*[\x27\x22`]?\s*$', prefix)
    line_prefix = content[max(left, content.rfind('\n', left, position) + 1):position]
    commented = bool(re.match(r'\s*(?://|#|\*)', line_prefix))
    if commented:
        assignment = None
    variable = assignment.group(1) if assignment else None
    role = 'unknown'
    if variable:
        folded = re.sub(r'[^a-z]', '', variable.lower())
        if any(word in folded for word in ('publickey', 'publishable', 'clientid')):
            role = 'public_identifier'
        elif any(word in folded for word in ('password', 'secret', 'token', 'apikey', 'accesskey', 'credential', 'privatekey')):
            role = 'credential'
        else:
            role = 'other'
        window = re.sub(r'(?<![\w$])' + re.escape(variable) + r'(?![\w$])', '__lhx_candidate__', window)
    parts = locator.lower().split('/')
    basename = parts[-1]
    file_role = 'application'
    if any(p in ('test', 'tests', '__tests__', 'fixtures', 'test_fixtures') for p in parts):
        file_role = 'test'
    elif any(p in ('docs', 'documentation', 'examples') for p in parts) or basename.startswith('readme') or basename.endswith(('.md', '.rst')):
        file_role = 'documentation'
    elif any(p in ('vendor', 'node_modules', 'dist', 'build', 'generated') for p in parts) or '.min.' in basename:
        file_role = 'generated'
    elif basename.startswith('.env') or basename.endswith(('.json', '.yaml', '.yml', '.ini', '.conf', '.properties', '.tfvars')):
        file_role = 'configuration'
    usage = []
    if commented or file_role == 'documentation':
        usage.append('comment_or_documentation')
    else:
        if re.search(r'authorization[\x27\x22]?\s*[:=][^\n;]{0,160}__lhx_candidate__', window, re.I):
            usage.append('authorization_header')
        if re.search(r'(?:configure|connect|createclient|client)\s*\([^\n;]{0,200}__lhx_candidate__', window, re.I):
            usage.append('client_configuration')
        if re.search(r'(?:export\s+(?:const|let|var|default)|module\.exports\s*=)[^\n;]{0,200}__lhx_candidate__', window):
            usage.append('exported_configuration')
        if rule in ('mongodb_uri', 'mysql_connection', 'postgres_connection', 'redis_connection'):
            usage.append('credential_in_connection_uri')
    sample = secret[:4096]
    entropy = -sum((n / len(sample)) * math.log2(n / len(sample)) for n in Counter(sample).values()) if sample else 0.0
    format_check = 'detector_pattern_match'
    if rule == 'generic_api_key':
        format_check = 'generic_assignment_pattern'
    elif rule == 'generic_pem_private_key':
        format_check = 'parsed_private_key'
    elif rule == 'jwt_token':
        format_check = 'parsed_jwt'
    elif rule in ('mongodb_uri', 'mysql_connection', 'postgres_connection', 'redis_connection'):
        format_check = 'parsed_connection_uri'
    # A caller outside the detector cannot manufacture a successful parse.
    if not valid_candidate(rule, secret, entropy):
        format_check = 'candidate_check_failed'
    body = re.sub(r'^(?:AKIA|ASIA|gh[pousr]_|github_pat_|(?:sk|rk)_(?:live|test)_)', '', secret)
    return dict(version=1, format_check=format_check, entropy_bits_per_character=round(entropy, 2),
                placeholder_detected=bool(placeholder(secret) or placeholder(body)),
                assignment='literal_assignment' if assignment else 'literal_without_assignment',
                variable_role=role, file_role=file_role, usage_categories=usage,
                candidate_references_in_window=min(100, max(1, window.count('__lhx_candidate__'))),
                window_chars=position-left + right-position-len(secret),
                window_truncated=bool(left or right < len(content)), analysis_method='bounded_lexical')
