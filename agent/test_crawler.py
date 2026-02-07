from crawler import CompleteCrawler
from domain_manager import DomainManager
from events.event_emitter import StdoutEmitter

# Create instances and run your crawl
dm = DomainManager('https://www.facebook.com')
crawler = CompleteCrawler(
    domain_manager=dm,
    config={'crawler_concurrency': 5, 'max_depth': 3}
)

print('✓ CompleteCrawler created successfully!')
print(f'  Domain: {crawler.domain_manager.base_domain}')
print(f'  Concurrency: {crawler.concurrency}')
print(f'  Max Depth: {crawler.max_depth}')
