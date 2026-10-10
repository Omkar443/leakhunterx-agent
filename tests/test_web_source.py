import pytest
from agent.sources.web import WebSource


def test_web_artifact_has_no_extra_network_and_hides_content_in_repr():
    source=WebSource('https://example.invalid/app.js','PRIVATE_ARTIFACT',16)
    with pytest.raises(RuntimeError): list(source.artifacts())
    source.prepare(); artifact=next(source.artifacts())
    assert artifact.source_type=='WEB' and artifact.locator.endswith('/app.js')
    assert artifact.content=='PRIVATE_ARTIFACT' and 'PRIVATE_ARTIFACT' not in repr(artifact)
    source.cleanup()
    assert source.content==''
    with pytest.raises(RuntimeError): list(source.artifacts())


@pytest.mark.parametrize('url',['file:///private/app.js','https://user:secret@example.invalid/a','local://123'])
def test_web_source_rejects_non_web_or_credential_urls(url):
    with pytest.raises(ValueError): WebSource(url,'text',4).prepare()
