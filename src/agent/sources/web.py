"""Web artifact adapter; discovery, network policy and downloads stay in the crawler.

An adapter owns one already-fetched resource, so adopting the common artifact
contract adds neither a second request nor an unbounded content buffer.
"""
import hashlib
from urllib.parse import urlsplit
from agent.sources.base import Artifact


class WebSource:
    def __init__(self, url, content, size, content_type='application/javascript'):
        self.url, self.content, self.size, self.content_type = url, content, size, content_type
        self._prepared = False

    def prepare(self):
        parsed = urlsplit(self.url)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Unsupported web artifact URL')
        if not isinstance(self.content,str) or type(self.size) is not int or self.size < 0:
            raise ValueError('Invalid web artifact')
        self._prepared = True

    def artifacts(self):
        if not self._prepared: raise RuntimeError('Web source not prepared')
        yield Artifact(hashlib.sha256(self.url.encode()).hexdigest(), 'WEB', self.url,
                       self.content_type, 'javascript', self.size,
                       hashlib.sha256(self.content.encode()).hexdigest(), self.content)

    def cleanup(self):
        self.content = ''
        self._prepared = False
