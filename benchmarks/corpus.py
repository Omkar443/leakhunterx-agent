"""Versioned synthetic fixtures. No registered credentials or provider calls.

Recipes, not secret-shaped blobs, are stored in Git. SHA-256 seeded bodies are
reproducible; expected values are independent of the detector under test.
"""
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).parent


def body(seed, length, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    data = hashlib.shake_256(seed.encode()).digest(length)
    return ''.join(alphabet[n % len(alphabet)] for n in data)


def token(kind, seed):
    if kind == 'aws': return 'AKIA' + body(seed, 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 'aws_access_key'
    if kind == 'aws_temporary': return 'ASIA' + body(seed, 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 'aws_access_key'
    if kind == 'github': return 'ghp_' + body(seed, 36), 'github_token'
    if kind == 'stripe': return 'sk_live_' + body(seed, 24), 'stripe_key'
    if kind == 'database': return 'postgresql://service:' + body(seed, 28) + '@db.example.invalid:5432/app', 'postgres_connection'
    if kind == 'jwt':
        def encode(value): return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).decode().rstrip('=')
        return encode({'alg':'HS256','typ':'JWT'}) + '.' + encode({'sub':seed,'iss':'lhx-benchmark'}) + '.' + body(seed,43), 'jwt_token'
    if kind == 'private_keys':
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode().strip(), 'generic_pem_private_key'
    if kind == 'generic': return body(seed, 40), 'generic_api_key'
    providers = {
        'google': ('AIza'+body(seed,35),'google_api_key'),
        'npm': ('npm_'+body(seed,36),'npm_token'),
        'github_fine': ('github_pat_'+body(seed,82),'github_fine_grained_pat'),
        'sendgrid': ('SG.'+body(seed,22)+'.'+body(seed+'tail',43),'sendgrid_api_key'),
        'anthropic': ('sk-ant-api03-'+body(seed,80),'anthropic_api_key'),
        'openai': ('sk-proj-'+body(seed,90),'openai_api_key'),
        'gitlab': ('glpat-'+body(seed,20),'gitlab_pat'),
        'huggingface': ('hf_'+body(seed,34),'huggingface_token'),
        'stripe_restricted': ('rk_live_'+body(seed,32),'stripe_restricted_key'),
        'slack': ('xoxb-'+body(seed,32),'slack_token'),
        'mongodb': ('mongodb+srv://service:'+body(seed,28)+'@db.example.invalid/app','mongodb_uri'),
        'mysql': ('mysql://service:'+body(seed,28)+'@db.example.invalid/app','mysql_connection'),
        'redis': ('redis://service:'+body(seed,28)+'@db.example.invalid/app','redis_connection'),
    }
    if kind in providers: return providers[kind]
    raise ValueError(kind)


def cases():
    for path in sorted(ROOT.glob('**/*.fixture.json')):
        spec = json.loads(path.read_text())
        for index in range(spec.get('count', 12)):
            seed = f"lhx-v1:{path.relative_to(ROOT).as_posix()}:{index}"
            kind = spec['kind']
            expected = []
            if spec['label'] == 'positive':
                value, rule = token(kind, seed)
                content = f'const api_key = "{value}";\nclient.authenticate(api_key);'
                expected = [(rule, value)]
                if spec.get('transform') == 'minified': content = '(()=>{' + 'var a=1;'*700 + content.replace('\n','') + '})();'
                if spec.get('transform') == 'huge': content = '/* ordinary application content */\n'*60000 + content
                if spec.get('transform') == 'duplicates': content += '\n' + content
            else:
                text = body(seed, 40)
                negative = {
                    'placeholder': 'const api_key = "YOUR_API_KEY_HERE_XXXXXXXX";',
                    'hash': f'const sha256 = "{hashlib.sha256(seed.encode()).hexdigest()}";',
                    'random': f'const buildId = "{text}";',
                    'public': 'const publicKey = "pk_live_' + text[:24] + '";',
                    'test': 'const secretKey = "sk_test_' + text[:24] + '";',
                    'database_no_password': 'const database = "postgresql://db.example.invalid/app";',
                    'key_header': 'The following is an example header: -----BEGIN PRIVATE KEY-----',
                    'jwt_invalid': 'const token = "eyJnotJSON.notJSON.notJSON";',
                    'docs_aws': 'AWS documentation key: ' + 'AKIA' + 'IOSFODNN7EXAMPLE',
                    'repeated': 'const api_key = "' + 'ab'*20 + '";',
                    'environment': 'const api_key = process.env.API_KEY;',
                    'storage': 'const bucket = "s3://public-assets";',
                }
                content = negative[kind]
            yield {'id':seed, 'path':path.relative_to(ROOT).as_posix(), 'split':spec.get('split','regression'),
                   'content':content, 'expected':expected}
