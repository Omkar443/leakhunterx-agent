"""Deterministic validation before AI. No network traffic, no raw-secret logging."""
import base64
import json
import re
from urllib.parse import urlsplit, unquote
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key

POLICY_VERSION = 'detector-v1'
EXPOSURE_RULES = frozenset({'s3_bucket','s3_url','google_storage','azure_storage',
    'twilio_account_sid','admin_endpoint','private_ip','api_endpoint_leak','credit_card',
    'recaptcha_key','segment_write_key','mixpanel_token','amplitude_api_key'})
KNOWN_EXAMPLES = frozenset({'AKIA'+'IOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'})
PEM_PATTERN = r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{16,16384}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'


def placeholder(value):
    folded = value.strip().lower()
    if value in KNOWN_EXAMPLES: return True
    if re.fullmatch(r'(?:your[_-]?(?:api[_-]?key|key|secret|token)|replace[_-]?me|placeholder|change[_-]?me|insert[_-]?key)(?:[_-]here|[_-]x+)*', folded): return True
    if re.fullmatch(r'(?:sk|rk|pk)_(?:live|test)_x+', folded): return True
    if len(value) > 7 and (len(set(value)) <= 2 or re.fullmatch(r'(.{1,4})\1{3,}', value)): return True
    return folded in {'example','dummy','notasecret','not_a_secret','test123','sample_key','todo','fixme'}


def valid_jwt(value):
    try:
        parts = value.split('.')
        if len(parts) != 3 or not parts[2] or len(value)>16384: return False
        objects = [json.loads(base64.urlsafe_b64decode(part + '='*(-len(part)%4))) for part in parts[:2]]
        return all(isinstance(obj, dict) for obj in objects) and isinstance(objects[0].get('alg'), str)
    except (ValueError, UnicodeError): return False


def valid_private_key(value):
    # Fully parse unencrypted keys; encrypted containers cannot be decrypted and
    # stay candidates only when their bounded PEM/DER envelope is structurally valid.
    try:
        data = value.encode('ascii')
        loader = load_ssh_private_key if value.startswith('-----BEGIN OPENSSH') else load_pem_private_key
        loader(data, password=None)
        return True
    except TypeError:
        # cryptography raises this specifically for encrypted keys without a password.
        return 'ENCRYPTED' in value or 'Proc-Type: 4,ENCRYPTED' in value
    except (ValueError, UnicodeError): return False


def valid_candidate(rule, value, entropy):
    if placeholder(value): return False
    if value.startswith(('pk_live_', 'pk_test_', 'sk_test_', 'rk_test_', 'pk.eyJ')): return False
    if rule == 'email_password' and '://' in value: return False
    if rule in ('generic_pem_private_key','ssh_private_key'): return valid_private_key(value)
    if rule == 'jwt_token': return valid_jwt(value)
    if rule in ('stripe_key','stripe_restricted_key'): return value.startswith(('sk_live_','rk_live_'))
    if rule == 'mapbox_token': return value.startswith('sk.')
    if rule.endswith(('connection','uri')) and rule in ('mongodb_uri','mysql_connection','postgres_connection','redis_connection'):
        try:
            parsed = urlsplit(value)
            return bool(parsed.hostname and parsed.password and not placeholder(unquote(parsed.password)))
        except ValueError: return False
    if rule == 'generic_api_key':
        # Entropy complements a credential assignment; random hashes alone never match.
        return len(value) >= 20 and entropy >= (2.8 if re.fullmatch('[a-fA-F0-9]+', value) else 3.2)
    return True


def update_patterns(patterns):
    # Endpoint/storage identifiers are inventoried by the endpoint engine.
    # Their mere existence is not a secret or evidence of unauthorized access.
    for rule in EXPOSURE_RULES:
        patterns.pop(rule, None)
    patterns['aws_access_key']['pattern'] = r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
    patterns['aws_access_key']['validation'] = lambda value: len(value)==20 and value.startswith(('AKIA','ASIA'))
    patterns['stripe_key']['pattern'] = r'\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,200}\b'
    patterns['generic_pem_private_key']['pattern'] = PEM_PATTERN
    if 'ssh_private_key' in patterns: patterns['ssh_private_key']['pattern'] = PEM_PATTERN
