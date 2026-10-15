from urllib.parse import urlsplit
from agent.local.asset_references import references


def test_ipv6_endpoint_authorities_remain_valid():
    for source in ('https://[::1]/', 'http://[2001:db8::1]/api', 'https://[::1]:443/a'):
        result=references(source)
        assert len(result)==1
        parsed=urlsplit(result[0]['locator'])
        assert parsed.hostname and parsed.port is None
        assert parsed.netloc.startswith('[') and parsed.netloc.endswith(']')


def test_canonical_reference_bound_matches_backend_contract():
    for source in ('https://example.org/'+('a/'*260),'https://[2001:db8::1]/'+('b/'*260)):
        assert all(len(item['locator'])<=512 for item in references(source))
