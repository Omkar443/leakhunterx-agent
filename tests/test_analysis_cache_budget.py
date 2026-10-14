import sys
from agent.js.js_analyzer import ContentCache


def test_cache_lru_is_bounded_by_storage_not_just_file_count():
    weight = sys.getsizeof('a'*50) + sys.getsizeof('x')
    cache = ContentCache(max_size=100, max_bytes=2*weight)
    cache.set('a','a'*50,50); cache.set('b','b'*50,50)
    assert cache.get('a') is not None
    cache.set('c','c'*50,50)
    assert cache.get('a') is not None and cache.get('b') is None
    assert cache.bytes_used <= cache.max_bytes
    cache.clear(); assert cache.bytes_used == 0


def test_oversized_and_unicode_entries_do_not_bypass_budget():
    cache = ContentCache(max_bytes=200)
    cache.set('a','small',5)
    cache.set('a','界'*100,300)
    assert cache.get('a') is None and cache.bytes_used == 0
    cache.set('b','x'*1000,1000)
    assert cache.get('b') is None and not cache._cache


def test_expired_entries_release_accounting(monkeypatch):
    from agent.js import js_analyzer
    now = [10]
    monkeypatch.setattr(js_analyzer.time,'time',lambda:now[0])
    cache = ContentCache(ttl_seconds=5)
    cache.set('a','code',4)
    assert cache.bytes_used > 0
    now[0] = 16
    assert cache.get('a') is None and cache.bytes_used == 0
    cache.set('a','new-code',8)
    assert cache.bytes_used == sys.getsizeof('a') + sys.getsizeof('new-code')
