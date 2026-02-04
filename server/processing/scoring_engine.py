# modules/scoring_engine.py
import yaml
import aiohttp
import asyncio
import socket
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
import logging
from .utils import print_status
from rich.console import Console

console = Console()

@dataclass
class SubdomainScore:
    """Scoring result with metadata"""
    subdomain: str
    total_score: int
    breakdown: Dict[str, Any]
    priority: str
    confidence: float
    http_info: Dict[str, Any]
    fingerprint: str

class ScoringEngine:
    """
    Smart Scoring Engine with Progressive Validation
    """

    def __init__(self, config_path: str = "config/scoring_rules.yaml"):
        # Initialize logger FIRST
        self.logger = self._setup_logger()
        self.config_path = config_path
        self.scoring_rules = self.load_scoring_rules()  # Now logger is available
        self.checked_domains = {}
        self.performance_cache = {}
        self.circuit_breaker = {}

        # Performance tracking
        self.total_scored = 0
        self.performance_metrics = {
            'avg_scoring_time': 0,
            'success_rate': 0,
            'cache_hits': 0
        }

    def _setup_logger(self):
        """Setup logging"""
        logger = logging.getLogger('scoring_engine')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def load_scoring_rules(self) -> Dict:
        """Load scoring rules with fallback"""
        try:
            with open(self.config_path, 'r') as f:
                rules = yaml.safe_load(f)['scoring']
                self._validate_scoring_rules(rules)
                console.print(f"    [green]✅ Loaded scoring rules from {self.config_path}[/green]")
                return rules
        except FileNotFoundError:
            self.logger.warning("Scoring config not found, using defaults")
            console.print(f"    [yellow]⚠️ Scoring config not found at {self.config_path}, using defaults[/yellow]")
            return self.get_default_rules()
        except Exception as e:
            self.logger.error(f"Error loading scoring rules: {e}, using defaults")
            console.print(f"    [red]❌ Error loading scoring rules: {e}[/red]")
            return self.get_default_rules()

    def _validate_scoring_rules(self, rules: Dict):
        """Validate scoring rules structure"""
        required_sections = ['keyword_tiers', 'status_scoring']
        for section in required_sections:
            if section not in rules:
                raise ValueError(f"Missing required scoring section: {section}")

    def get_default_rules(self) -> Dict:
        """Default scoring rules"""
        console.print("    [yellow]⚠️ Using default scoring rules[/yellow]")
        return {
            'keyword_tiers': {
                'CRITICAL': {'api': 25, 'admin': 22, 'auth': 20, 'secure': 18},
                'HIGH': {'app': 15, 'portal': 15, 'dashboard': 15},
                'MEDIUM': {'dev': 8, 'test': 8, 'staging': 8},
                'LOW': {'mail': 3, 'cdn': 2, 'static': 2}
            },
            'status_scoring': {
                'alive': 30, 'status_200': 25, 'status_302': 20,
                'status_401': 15, 'status_403': 12, 'js_present': 20
            },
            'cloud_services': {
                's3': 15, 'azure': 15, 'gcp': 15, 'cloudfront': 12
            },
            'tech_stack': {
                'jenkins': 20, 'grafana': 20, 'kibana': 20, 'phpmyadmin': 22
            },
            'priority_thresholds': {
                'CRITICAL': 80, 'HIGH': 50, 'MEDIUM': 25, 'LOW': 0
            }
        }

    def _generate_fingerprint(self, subdomain: str, http_info: Dict) -> str:
        """Generate unique fingerprint for subdomain"""
        fingerprint_data = f"{subdomain}:{http_info.get('ip', '')}:{http_info.get('status_code', 0)}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()

    def calculate_keyword_score(self, subdomain: str) -> int:
        """Keyword scoring with tier system"""
        score = 0
        subdomain_lower = subdomain.lower()

        for tier, keywords in self.scoring_rules['keyword_tiers'].items():
            for keyword, points in keywords.items():
                if keyword in subdomain_lower:
                    score += points
                    # Enhanced UI with color coding
                    color = {
                        'CRITICAL': 'red',
                        'HIGH': 'yellow',
                        'MEDIUM': 'blue',
                        'LOW': 'cyan'
                    }.get(tier, 'white')
                    console.print(f"        [{color}]+{points} for {tier} keyword: {keyword}[/{color}]")

        return score

    async def check_dns_resolution(self, domain: str) -> bool:
        """DNS resolution check with caching"""
        if domain in self.performance_cache:
            return self.performance_cache[domain].get('dns_resolves', False)

        try:
            socket.getaddrinfo(domain, 443, family=socket.AF_INET)
            result = True
        except socket.gaierror:
            result = False

        # Cache result
        if domain not in self.performance_cache:
            self.performance_cache[domain] = {}
        self.performance_cache[domain]['dns_resolves'] = result

        return result

    def _ensure_http_url(self, domain: str) -> str:
        """Ensure domain has proper HTTP protocol for testing"""
        # If already has protocol, return as-is
        if domain.startswith(('http://', 'https://')):
            return domain
        
        # Try HTTPS first, then HTTP fallback
        return f"https://{domain}"

    async def check_http_status(self, domain: str) -> Dict[str, Any]:
        """HTTP status check with protocol handling"""
        result = {
            'alive': False,
            'status_code': 0,
            'has_js': False,
            'headers': {},
            'ip': None,
            'response_time': 0,
            'final_url': domain
        }

        start_time = time.time()

        # Test both HTTPS and HTTP if needed
        test_urls = []
        
        # If domain already has protocol, use it directly
        if domain.startswith(('http://', 'https://')):
            test_urls.append(domain)
        else:
            # Try HTTPS first, then HTTP as fallback
            test_urls.append(f"https://{domain}")
            test_urls.append(f"http://{domain}")

        connector = aiohttp.TCPConnector(limit=5, limit_per_host=3, ssl=False)
        timeout = aiohttp.ClientTimeout(total=8, connect=4)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for test_url in test_urls:
                try:
                    # Enhanced UI with status indicator
                    console.print(f"        [blue]Testing: {test_url}[/blue]")
                    
                    async with session.get(
                        test_url,
                        ssl=False,
                        allow_redirects=True
                    ) as response:

                        result['alive'] = True
                        result['status_code'] = response.status
                        result['headers'] = dict(response.headers)
                        result['response_time'] = time.time() - start_time
                        result['final_url'] = str(response.url)

                        # Get IP address
                        if response.connection and response.connection.transport:
                            peername = response.connection.transport.get_extra_info('peername')
                            if peername:
                                result['ip'] = str(peername[0])

                        # JS detection
                        content_type = response.headers.get('content-type', '').lower()
                        if any(ct in content_type for ct in ['text/html', 'application/javascript', 'text/javascript']):
                            text = await response.text(errors='ignore')
                            js_indicators = ['<script', 'function', 'var ', 'const ', 'let ', '.js']
                            if any(indicator in text.lower() for indicator in js_indicators):
                                result['has_js'] = True

                        # Success - break out of URL testing loop
                        status_color = 'green' if response.status == 200 else 'yellow' if response.status < 400 else 'red'
                        console.print(f"        [{status_color}]✓ HTTP {response.status} ({result['response_time']:.2f}s)[/{status_color}]")
                        break

                except aiohttp.ClientConnectorSSLError:
                    # SSL error - try HTTP if we haven't already
                    if test_url.startswith('https://') and f"http://{domain.split('//')[-1]}" not in test_urls:
                        continue  # Will try HTTP next
                    console.print(f"        [red]✗ SSL connection failed[/red]")
                    result['error'] = "SSL connection failed"
                except aiohttp.ClientConnectorError:
                    # Connection error - try next protocol
                    console.print(f"        [yellow]⚠ Connection failed, trying next protocol...[/yellow]")
                    continue
                except asyncio.TimeoutError:
                    console.print(f"        [red]✗ Request timeout (8s)[/red]")
                    result['error'] = "Request timeout"
                    break
                except Exception as e:
                    console.print(f"        [red]✗ Error: {str(e)[:50]}[/red]")
                    result['error'] = str(e)
                    # Don't break - try next URL

        return result

    def calculate_live_score(self, http_info: Dict) -> int:
        """Live scoring with response time factor and baseline scoring"""
        score = 0
        rules = self.scoring_rules['status_scoring']

        # BASELINE SCORING: Give points for DNS resolution
        if http_info.get('alive', False):
            score += rules['alive']
            console.print(f"        [green]+{rules['alive']} for alive domain[/green]")

            status_code = http_info.get('status_code', 0)
            status_key = f'status_{status_code}'
            if status_key in rules:
                score += rules[status_key]
                color = 'green' if status_code == 200 else 'yellow' if status_code < 400 else 'red'
                console.print(f"        [{color}]+{rules[status_key]} for status {status_code}[/{color}]")

            if http_info.get('has_js', False):
                score += rules['js_present']
                console.print(f"        [green]+{rules['js_present']} for JS present[/green]")
        else:
            # MINIMUM SCORE FOR DNS-RESOLVABLE DOMAINS
            # Even if HTTP fails, if DNS resolves, give some points
            if 'dns_resolves' in http_info and http_info['dns_resolves']:
                score += 5  # Baseline for DNS resolution
                console.print(f"        [cyan]+5 for DNS resolution[/cyan]")

        return score

    def determine_priority(self, total_score: int) -> str:
        """Determine priority level based on score"""
        thresholds = self.scoring_rules['priority_thresholds']

        if total_score >= thresholds['CRITICAL']:
            return 'CRITICAL'
        elif total_score >= thresholds['HIGH']:
            return 'HIGH'
        elif total_score >= thresholds['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'

    async def score_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Subdomain scoring with metadata and protocol handling"""
        start_time = time.time()
        
        # Enhanced UI with visual indicator
        console.print(f"    [cyan]🎯 Scoring: {subdomain}[/cyan]")

        # Check cache first
        cache_key = f"score_{subdomain}"
        if cache_key in self.performance_cache:
            self.performance_metrics['cache_hits'] += 1
            cached_result = self.performance_cache[cache_key]
            console.print(f"    [yellow]⚠ Using cached result for {subdomain} (Score: {cached_result['score']})[/yellow]")
            return cached_result

        score_breakdown = {}
        total_score = 0

        # Keyword-based scoring
        keyword_score = self.calculate_keyword_score(subdomain)
        score_breakdown['keywords'] = keyword_score
        total_score += keyword_score

        # Live checking (DNS + HTTP)
        dns_resolves = await self.check_dns_resolution(subdomain)
        
        if dns_resolves:
            http_info = await self.check_http_status(subdomain)
            http_info['dns_resolves'] = True  # Track DNS success
            
            live_score = self.calculate_live_score(http_info)
            score_breakdown['live'] = live_score
            total_score += live_score
            score_breakdown['http_info'] = http_info
        else:
            score_breakdown['live'] = 0
            score_breakdown['http_info'] = {'alive': False, 'dns_resolves': False}
            console.print(f"    [red]✗ DNS resolution failed for {subdomain}[/red]")

        # ENSURE MINIMUM SCORE FOR VALID DOMAINS
        if dns_resolves and total_score < 10:
            total_score = 10  # Minimum score for DNS-resolvable domains
            console.print(f"    [cyan]Applied minimum score 10 for DNS-resolvable domain[/cyan]")

        # Final calculations
        score_breakdown['total'] = total_score
        priority = self.determine_priority(total_score)
        fingerprint = self._generate_fingerprint(subdomain, score_breakdown.get('http_info', {}))

        result = {
            'subdomain': subdomain,
            'score': total_score,
            'breakdown': score_breakdown,
            'priority': priority,
            'fingerprint': fingerprint,
            'scoring_time': time.time() - start_time,
            'dns_resolves': dns_resolves
        }

        # Cache the result
        self.performance_cache[cache_key] = result
        self.total_scored += 1

        # Enhanced UI with color-coded priority
        priority_color = {
            'CRITICAL': 'red',
            'HIGH': 'yellow',
            'MEDIUM': 'blue',
            'LOW': 'cyan'
        }.get(priority, 'white')
        
        console.print(f"    [{priority_color}]📊 {subdomain} - Score: {total_score} [{priority}][/{priority_color}]")
        return result

    async def score_subdomains_batch(self, subdomains: List[str], max_concurrent: int = 10) -> List[Dict]:
        """Batch scoring with performance tracking and protocol handling"""
        if not subdomains:
            console.print("    [yellow]⚠️ No subdomains to score[/yellow]")
            return []

        console.print(f"    [blue]🧠 Scoring {len(subdomains)} subdomains...[/blue]")
        
        start_time = time.time()

        # Process in optimized batches
        batch_size = min(max_concurrent, 10)
        all_scored = []
        successful = 0

        # Show progress visualization
        total_batches = (len(subdomains) + batch_size - 1) // batch_size
        
        for batch_num, i in enumerate(range(0, len(subdomains), batch_size), 1):
            if self._should_stop():
                break
                
            batch = subdomains[i:i + batch_size]
            
            # Show batch progress
            progress_percent = (batch_num / total_batches) * 100
            progress_bar = "█" * int(progress_percent / 5) + "░" * (20 - int(progress_percent / 5))
            console.print(f"    [cyan]📦 Batch {batch_num}/{total_batches} ({len(batch)} domains) {progress_bar} {progress_percent:.1f}%[/cyan]")

            tasks = [self.score_subdomain(subdomain) for subdomain in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in batch_results:
                if isinstance(result, dict):
                    all_scored.append(result)
                    if result['score'] > 0:
                        successful += 1
                elif isinstance(result, Exception):
                    console.print(f"    [red]✗ Error in batch processing: {result}[/red]")

            # Small delay between batches
            await asyncio.sleep(0.1)

        # Update performance metrics
        total_time = time.time() - start_time
        self.performance_metrics['avg_scoring_time'] = total_time / len(subdomains) if subdomains else 0
        self.performance_metrics['success_rate'] = (successful / len(subdomains)) if subdomains else 0

        # Sort by score descending
        all_scored.sort(key=lambda x: x['score'], reverse=True)

        # Show scoring summary
        console.print(f"    [green]✅ Scoring completed: {successful}/{len(subdomains)} successful[/green]")
        
        # Show top findings with enhanced visualization
        if successful > 0:
            # Count by priority
            priority_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for domain in all_scored:
                priority = domain.get('priority', 'LOW')
                if priority in priority_counts:
                    priority_counts[priority] += 1
            
            # Show summary
            console.print(f"    [blue]📊 Priority Distribution:[/blue]")
            for priority, count in priority_counts.items():
                if count > 0:
                    color = {
                        'CRITICAL': 'red',
                        'HIGH': 'yellow',
                        'MEDIUM': 'blue',
                        'LOW': 'cyan'
                    }.get(priority, 'white')
                    console.print(f"        [{color}]• {priority}: {count} domains[/{color}]")
            
            # Show top 3 high-risk findings
            high_risk = [d for d in all_scored if d.get('priority', 'LOW') in ['HIGH', 'CRITICAL']][:3]
            if high_risk:
                console.print(f"    [red]🚨 Top High-Risk Targets:[/red]")
                for i, domain in enumerate(high_risk, 1):
                    subdomain_name = domain['subdomain']
                    priority = domain.get('priority', 'MEDIUM')
                    score = domain.get('score', 0)
                    color = 'red' if priority == 'CRITICAL' else 'yellow'
                    console.print(f"        [{color}]{i}. {subdomain_name} (Score: {score}, {priority})[/{color}]")
        
        return all_scored

    def get_top_scorers(self, scored_domains: List[Dict], top_n: int = 50) -> List[Dict]:
        """Get top N scoring subdomains"""
        return scored_domains[:top_n]

    def print_scoring_summary(self, scored_domains: List[Dict]):
        """Enhanced scoring summary with visual elements"""
        if not scored_domains:
            console.print("    [yellow]⚠️ No domains scored[/yellow]")
            return

        top_score = scored_domains[0]['score'] if scored_domains else 0
        avg_score = sum(s['score'] for s in scored_domains) / len(scored_domains) if scored_domains else 0

        # Priority distribution
        priority_count = {}
        for domain in scored_domains:
            priority = domain.get('priority', 'LOW')
            priority_count[priority] = priority_count.get(priority, 0) + 1

        # Count high-risk (HIGH + CRITICAL)
        high_risk_count = priority_count.get('HIGH', 0) + priority_count.get('CRITICAL', 0)

        # Enhanced UI with visual elements
        console.print("    [blue]┌──────────────────────────────────────────────────────────────┐[/blue]")
        console.print("    [blue]│                    Scoring Summary                          │[/blue]")
        console.print("    [blue]├──────────────────────────────────────────────────────────────┤[/blue]")
        console.print(f"    [blue]│ Total Scored          : [/blue][white]{len(scored_domains):>30}[/white] [blue]│[/blue]")
        console.print(f"    [blue]│ High-Risk Domains     : [/blue][red]{high_risk_count:>30}[/red] [blue]│[/blue]")
        console.print(f"    [blue]│ Average Score         : [/blue][white]{avg_score:>30.1f}[/white] [blue]│[/blue]")
        console.print(f"    [blue]│ Top Score             : [/blue][green]{top_score:>30}[/green] [blue]│[/blue]")
        
        # Show priority distribution
        if priority_count:
            console.print("    [blue]├──────────────────────────────────────────────────────────────┤[/blue]")
            console.print("    [blue]│ Priority Distribution                                       │[/blue]")
            for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = priority_count.get(priority, 0)
                if count > 0:
                    color = {
                        'CRITICAL': 'red',
                        'HIGH': 'yellow',
                        'MEDIUM': 'blue',
                        'LOW': 'cyan'
                    }.get(priority, 'white')
                    
                    # Create a simple bar visualization
                    bar_length = int((count / len(scored_domains)) * 30)
                    bar = "█" * bar_length + "░" * (30 - bar_length)
                    
                    console.print(f"    [blue]│ [/blue][{color}]{priority:<9}[/{color}] [blue]: {count:>4} [/blue][white]{bar}[/white] [blue]│[/blue]")
        
        console.print("    [blue]└──────────────────────────────────────────────────────────────┘[/blue]")

    def _should_stop(self):
        """Check if should stop processing"""
        return False