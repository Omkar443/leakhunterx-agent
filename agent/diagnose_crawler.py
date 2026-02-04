#!/usr/bin/env python3
"""
Diagnose why crawler isn't finding JS files
"""

import asyncio
import logging
from domain_manager import DomainManager
from crawler import CompleteCrawler, CrawlContext
from events.event_emitter import create_emitter

logging.basicConfig(level=logging.INFO)

async def test_crawler():
    print("🔍 DIAGNOSING CRAWLER ISSUE")
    print("=" * 70)
    
    # Test with a simple target
    target_url = "https://www.tesla.com"
    
    # Create emitter
    emitter = create_emitter("stdout", config={})
    await emitter.start()
    
    # Create DomainManager (with discovery)
    dm = DomainManager(target_url=target_url, max_depth=2)
    dm.add_seed_urls([target_url])
    
    print(f"1. DomainManager created for: {target_url}")
    print(f"   Base domain: {dm.base_domain}")
    print(f"   Initial queue size: {dm.get_queue_size()}")
    
    # Manually add some subdomains (simulating discovery)
    subdomains = [
        "https://auth.tesla.com",
        "https://static.tesla.com",
        "https://mobile.tesla.com",
    ]
    
    for subdomain in subdomains:
        added, reason = dm.add_discovered(subdomain, depth=0, source_url="test")
        print(f"   {subdomain}: {'✓' if added else '✗'} {reason}")
    
    print(f"\n2. Total URLs in queue: {dm.get_queue_size()}")
    print(f"   JS queue size: {dm.get_js_queue_size()}")
    
    # Create crawler
    crawler = CompleteCrawler(
        domain_manager=dm,
        config={
            "crawler_concurrency": 3,
            "max_depth": 2,
            "max_pages": 10,
            "timeout": 30,
            "user_agent": "Mozilla/5.0 (compatible; LeakHunterX/1.0; +https://leakhunterx.com)"
        }
    )
    
    # Create crawl context
    context = CrawlContext(
        scan_id="test_crawler_001",
        domain_manager=dm,
        event_emitter=emitter,
        config={}
    )
    
    print("\n3. Running crawler...")
    try:
        await asyncio.wait_for(crawler.crawl(context), timeout=60)
        
        print(f"\n4. Crawler completed")
        print(f"   Total discovered: {dm.stats['total_discovered']}")
        print(f"   JS files found: {dm.get_js_queue_size()}")
        print(f"   URLs processed: {dm.stats['urls_processed']}")
        
        stats = dm.get_stats()
        print(f"\n5. DomainManager stats:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        if dm.get_js_queue_size() > 0:
            print("\n✅ CRAWLER IS FINDING JS FILES")
            return True
        else:
            print("\n❌ CRAWLER FOUND NO JS FILES")
            print("   Possible reasons:")
            print("   • Site blocking crawler")
            print("   • No JavaScript files on pages")
            print("   • Crawler timeout/errors")
            return False
            
    except asyncio.TimeoutError:
        print("❌ Crawler timed out")
        return False
    except Exception as e:
        print(f"❌ Crawler error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        await emitter.close()

if __name__ == "__main__":
    success = asyncio.run(test_crawler())
    exit(0 if success else 1)
