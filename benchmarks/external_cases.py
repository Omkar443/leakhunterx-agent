"""External-format challenge, frozen before detector changes on 2026-10-09.

Presentation templates and placeholder cases adapted from Gitleaks (MIT),
revision b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b. No upstream code executes.
Values are newly generated synthetic candidates, never registered credentials.
This supplements the tuned v1 corpus; it is not human-labelled production data.
"""
import base64
import hashlib
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

UPSTREAM = 'https://github.com/gitleaks/gitleaks/tree/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config'
FORMATS = {
    'ini-unquoted': '{i}Token={s}',
    'json': '{{"{i}_token": "{s}"}}',
    'xml-multiline': '<{i}Token>\n    {s}\n</{i}Token>',
    'yaml': '{i}_token: \'{s}\'',
    'go-backticks': '{i}Token := `{s}`',
    'logstash': '"{i}Token" => "{s}"',
}


def body(seed, size, alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    material = hashlib.shake_256(('external-format-v1:' + seed).encode()).digest(size)
    return ''.join(alphabet[n % len(alphabet)] for n in material)


def specimens():
    aws = body('aws', 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
    github = body('github', 36)
    fine = body('fine', 21) + '_' + body('fine-rest', 60)
    stripe = body('stripe', 32)
    encode = lambda obj: base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode()).decode().rstrip('=')
    jwt = encode({'alg': 'HS256', 'typ': 'JWT'}) + '.' + encode({'sub': 'external-synthetic', 'iss': 'lhx-external-format'}) + '.' + body('signature', 43)
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'external-format-v1-private').digest())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode().strip()
    positives = [
        ('aws', 'AKIA' + aws, 'aws_access_key'), ('temporary-aws', 'ASIA' + aws, 'aws_access_key'),
        ('github', 'ghp_' + github, 'github_token'), ('fine-grained-github', 'github_pat_' + fine, 'github_fine_grained_pat'),
        ('stripe', 'sk_live_' + stripe, 'stripe_key'), ('jwt', jwt, 'jwt_token'),
        ('database', 'postgresql://service:' + body('database', 28) + '@db.example.invalid/app', 'postgres_connection'),
        ('private-key', pem, 'generic_pem_private_key'),
    ]
    negatives = [
        ('github-placeholder', 'ghp_' + 'x' * 36),
        ('fine-grained-placeholder', 'github_pat_' + 'x' * 22 + '_' + 'x' * 59),
        ('github-overlong', 'ghp_' + github + 'Q'), ('fine-grained-short', 'github_pat_' + fine[:-1]),
        ('aws-placeholder', 'AKIA' + 'X' * 16), ('documented-aws', 'AKIA' + 'IOSFODNN7EXAMPLE'),
        ('publishable-stripe', 'pk_live_' + stripe), ('test-stripe', 'sk_test_' + stripe),
        ('no-password-database', 'postgresql://db.example.invalid/app'), ('malformed-jwt', 'eyJnotJSON.notJSON.notJSON'),
        ('header-only-private-key', '-----BEGIN PRIVATE KEY-----'),
        ('invalid-private-key', '-----BEGIN PRIVATE KEY-----\nanything\n-----END PRIVATE KEY-----'),
    ]
    return positives, negatives


def cases():
    positives, negatives = specimens()
    for name, template in FORMATS.items():
        for kind, value, rule in positives:
            yield {'id': f'external-v1:{name}:{kind}', 'path': f'formats/{name}/{kind}.txt', 'split': 'external-format',
                   'content': template.format(i=kind.replace('-', ''), s=value), 'expected': [(rule, value)]}
        for kind, value in negatives:
            yield {'id': f'external-v1:{name}:{kind}', 'path': f'negatives/{name}/{kind}.txt', 'split': 'external-format',
                   'content': template.format(i='credential', s=value), 'expected': []}
