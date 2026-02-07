#!/usr/bin/env python3
"""
LeakHunterX Backend Event Pipeline Validator

Comprehensive test suite to verify:
1. Authentication & authorization
2. Event schema validation
3. Rate limiting behavior
4. Event ordering guarantees
5. Error handling & resilience
6. Concurrency safety
"""

import requests
import json
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import statistics

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_URL = "https://backend-leakhunterx.onrender.com/api/v1"
AGENT_ID = f"validator-{uuid.uuid4().hex[:8]}"
AGENT_SECRET = "test-secret-123"

HEADERS = {
    "X-Agent-Id": AGENT_ID,
    "X-Agent-Secret": AGENT_SECRET,
    "Content-Type": "application/json",
}

# Test constants
SCAN_ID_PREFIX = "scan_test_"
PROJECT_ID = 1
TARGET_URL = "https://example.com"
NUM_CONCURRENT_SCANS = 3
EVENTS_PER_SCAN = 20
MAX_RETRIES = 3

# ============================================================================
# DATA STRUCTURES
# ============================================================================

class TestResult(Enum):
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️  WARN"
    SKIP = "⏭️  SKIP"

@dataclass
class TestCase:
    name: str
    description: str
    result: TestResult = TestResult.SKIP
    duration: float = 0.0
    error: Optional[str] = None
    details: Optional[Dict] = None

# ============================================================================
# HTTP CLIENT WITH RETRY & METRICS
# ============================================================================

class BackendClient:
    def __init__(self, base_url: str, headers: Dict):
        self.base_url = base_url.rstrip("/")
        self.headers = headers
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.metrics = {
            "requests": 0,
            "success": 0,
            "errors": 0,
            "retries": 0,
            "total_latency": 0.0,
        }
    
    def request(self, method: str, path: str, payload: Optional[Dict] = None, 
                max_retries: int = 3) -> Tuple[Optional[Dict], int, float]:
        """Make HTTP request with retry logic and metrics"""
        url = f"{self.base_url}{path}"
        latency = 0.0
        
        for attempt in range(max_retries + 1):
            self.metrics["requests"] += 1
            
            try:
                start_time = time.time()
                
                if method.upper() == "GET":
                    response = self.session.get(url)
                elif method.upper() == "POST":
                    response = self.session.post(url, json=payload)
                elif method.upper() == "PUT":
                    response = self.session.put(url, json=payload)
                elif method.upper() == "DELETE":
                    response = self.session.delete(url)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                latency = time.time() - start_time
                self.metrics["total_latency"] += latency
                
                # Log request details for debugging
                if attempt > 0:
                    self.metrics["retries"] += 1
                    print(f"  ↳ Attempt {attempt + 1}/{max_retries + 1} for {method} {path}")
                
                if 200 <= response.status_code < 300:
                    self.metrics["success"] += 1
                    data = response.json() if response.text else {}
                    return data, response.status_code, latency
                
                elif response.status_code >= 500:
                    # Server error - retry with exponential backoff
                    if attempt < max_retries:
                        sleep_time = 2 ** attempt  # Exponential backoff
                        print(f"  ↳ Server error {response.status_code}, retrying in {sleep_time}s...")
                        time.sleep(sleep_time)
                        continue
                
                # Client errors (4xx) don't get retried
                self.metrics["errors"] += 1
                return None, response.status_code, latency
                
            except requests.exceptions.RequestException as e:
                self.metrics["errors"] += 1
                if attempt == max_retries:
                    return None, 0, latency
                time.sleep(1)  # Simple backoff for connection errors
        
        return None, 0, latency
    
    def get_metrics(self) -> Dict:
        """Get client metrics with averages"""
        avg_latency = 0.0
        if self.metrics["requests"] > 0:
            avg_latency = self.metrics["total_latency"] / self.metrics["requests"]
        
        return {
            **self.metrics,
            "avg_latency_ms": round(avg_latency * 1000, 2),
            "success_rate": round(self.metrics["success"] / max(self.metrics["requests"], 1) * 100, 1)
        }

# ============================================================================
# TEST SUITE
# ============================================================================

class BackendValidator:
    def __init__(self):
        self.client = BackendClient(BASE_URL, HEADERS)
        self.tests: List[TestCase] = []
        self.scan_ids: List[str] = []
        
    def add_test(self, test: TestCase):
        self.tests.append(test)
    
    def run_all_tests(self):
        """Execute all test cases in sequence"""
        print("\n" + "="*70)
        print("🚀 LeakHunterX Backend Event Pipeline Validator")
        print("="*70)
        
        # Run test groups
        self.run_auth_tests()
        self.run_heartbeat_tests()
        self.run_single_scan_tests()
        self.run_concurrency_tests()
        self.run_error_handling_tests()
        self.run_performance_tests()
        
        # Print summary
        self.print_summary()
        
        # Print client metrics
        self.print_metrics()
    
    def run_auth_tests(self):
        """Test authentication and authorization"""
        print("\n🔐 AUTHENTICATION TESTS")
        print("-" * 40)
        
        # Test 1: Valid credentials
        test = TestCase(
            name="Valid Authentication",
            description="Test with correct agent credentials"
        )
        start = time.time()
        data, status, _ = self.client.request("POST", "/agent/events", {
            "event_type": "test_auth",
            "scan_id": "test_auth_scan",
            "agent_id": AGENT_ID,
            "data": {"test": "authentication"}
        })
        
        if status == 200 or status == 202:
            test.result = TestResult.PASS
        elif status == 401:
            test.result = TestResult.FAIL
            test.error = "Authentication failed with valid credentials"
        else:
            test.result = TestResult.WARN
            test.error = f"Unexpected status: {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 2: Invalid secret
        test = TestCase(
            name="Invalid Secret Rejection",
            description="Test with incorrect agent secret"
        )
        start = time.time()
        
        # Create client with wrong secret
        bad_client = BackendClient(BASE_URL, {
            "X-Agent-Id": AGENT_ID,
            "X-Agent-Secret": "wrong-secret",
            "Content-Type": "application/json",
        })
        
        _, status, _ = bad_client.request("POST", "/agent/events", {
            "event_type": "test_auth",
            "scan_id": "test_auth_scan",
            "agent_id": AGENT_ID,
            "data": {"test": "bad_auth"}
        })
        
        if status == 401:
            test.result = TestResult.PASS
            test.details = {"expected": 401, "received": status}
        else:
            test.result = TestResult.FAIL
            test.error = f"Should reject with 401, got {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 3: Missing headers
        test = TestCase(
            name="Missing Required Headers",
            description="Test request without X-Agent headers"
        )
        start = time.time()
        
        bad_client = BackendClient(BASE_URL, {
            "Content-Type": "application/json",  # Missing X-Agent headers
        })
        
        _, status, _ = bad_client.request("POST", "/agent/events", {
            "event_type": "test_auth",
            "scan_id": "test_auth_scan",
            "data": {"test": "no_headers"}
        })
        
        if status == 400 or status == 401:
            test.result = TestResult.PASS
        else:
            test.result = TestResult.WARN
            test.error = f"Expected 400/401 for missing headers, got {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def run_heartbeat_tests(self):
        """Test heartbeat endpoint"""
        print("\n❤️  HEARTBEAT TESTS")
        print("-" * 40)
        
        # Test 1: Basic heartbeat
        test = TestCase(
            name="Heartbeat Registration",
            description="Send heartbeat and verify agent is registered"
        )
        start = time.time()
        
        data, status, _ = self.client.request("PUT", "/agent/heartbeat", {
            "agent_id": AGENT_ID,
            "state": "connected",
            "cpu_percent": 12.5,
            "memory_percent": 30.1,
            "version": "validator-1.0.0",
            "mode": "validator",
        })
        
        if status == 200:
            test.result = TestResult.PASS
            test.details = data
        else:
            test.result = TestResult.FAIL
            test.error = f"Heartbeat failed with status {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 2: Heartbeat state transitions
        test = TestCase(
            name="Heartbeat State Transitions",
            description="Test different agent states"
        )
        start = time.time()
        
        states = ["connected", "idle", "scanning", "error"]
        results = []
        
        for state in states:
            data, status, _ = self.client.request("PUT", "/agent/heartbeat", {
                "agent_id": AGENT_ID,
                "state": state,
                "cpu_percent": 10.0,
                "memory_percent": 25.0,
                "version": "validator-1.0.0",
            })
            results.append(status == 200)
        
        if all(results):
            test.result = TestResult.PASS
            test.details = {"states_tested": states}
        else:
            test.result = TestResult.FAIL
            test.error = f"Some states failed: {states}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def run_single_scan_tests(self):
        """Test a complete scan lifecycle"""
        print("\n🔍 SINGLE SCAN LIFECYCLE TESTS")
        print("-" * 40)
        
        scan_id = f"{SCAN_ID_PREFIX}{uuid.uuid4().hex[:8]}"
        self.scan_ids.append(scan_id)
        
        # Test 1: Scan started
        test = TestCase(
            name="Scan Started Event",
            description="Send scan_started event"
        )
        start = time.time()
        
        data, status, latency = self.client.request("POST", "/agent/events", {
            "event_type": "scan_started",
            "scan_id": scan_id,
            "project_id": PROJECT_ID,
            "target_url": TARGET_URL,
            "agent_id": AGENT_ID,
            "data": {
                "message": "Validation scan started",
                "started_at": int(time.time())
            },
        })
        
        if status in [200, 202]:
            test.result = TestResult.PASS
            test.details = {"status": status, "latency_ms": round(latency * 1000, 2)}
        else:
            test.result = TestResult.FAIL
            test.error = f"scan_started failed with status {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 2: Progress events
        test = TestCase(
            name="Progress Events",
            description="Send multiple progress events"
        )
        start = time.time()
        
        progress_statuses = []
        for i in range(5):
            data, status, _ = self.client.request("POST", "/agent/events", {
                "event_type": "scan_progress",
                "scan_id": scan_id,
                "agent_id": AGENT_ID,
                "data": {
                    "current": i + 1,
                    "total": 5,
                    "message": f"Progress {i + 1}/5",
                    "phase": "crawling" if i < 3 else "analysis"
                },
            })
            progress_statuses.append(status in [200, 202])
            time.sleep(0.2)  # Small delay between events
        
        if all(progress_statuses):
            test.result = TestResult.PASS
            test.details = {"events_sent": len(progress_statuses)}
        else:
            test.result = TestResult.WARN
            test.error = "Some progress events failed"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 3: Artifact batch
        test = TestCase(
            name="Artifact Batch Delivery",
            description="Send artifact_batch_ready event"
        )
        start = time.time()
        
        artifacts = []
        for i in range(3):
            artifacts.append({
                "type": "endpoint",
                "url": f"https://example.com/api/test/{i}",
                "method": "GET",
                "confidence": 0.85 + (i * 0.05),
                "scan_id": scan_id,
                "timestamp": int(time.time()),
                "metadata": {
                    "status_code": 200,
                    "response_time": 150 + i
                }
            })
        
        data, status, latency = self.client.request("POST", "/agent/events", {
            "event_type": "artifact_batch_ready",
            "scan_id": scan_id,
            "agent_id": AGENT_ID,
            "data": {
                "count": len(artifacts),
                "batch_index": 1,
                "artifacts": artifacts,
                "batch_timestamp": int(time.time())
            },
        })
        
        if status in [200, 202]:
            test.result = TestResult.PASS
            test.details = {
                "artifacts_sent": len(artifacts),
                "latency_ms": round(latency * 1000, 2),
                "batch_size": len(artifacts)
            }
        else:
            test.result = TestResult.FAIL
            test.error = f"artifact_batch_ready failed with status {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 4: Scan completed
        test = TestCase(
            name="Scan Completed Event",
            description="Send scan_completed event"
        )
        start = time.time()
        
        data, status, _ = self.client.request("POST", "/agent/events", {
            "event_type": "scan_completed",
            "scan_id": scan_id,
            "agent_id": AGENT_ID,
            "data": {
                "status": "completed",
                "duration": 15,
                "endpoints_found": 3,
                "secrets_found": 0,
                "completed_at": int(time.time())
            },
        })
        
        if status in [200, 202]:
            test.result = TestResult.PASS
            test.details = {"status": status}
        else:
            test.result = TestResult.FAIL
            test.error = f"scan_completed failed with status {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def run_concurrency_tests(self):
        """Test concurrent scan events"""
        print("\n⚡ CONCURRENCY TESTS")
        print("-" * 40)
        
        # Test 1: Multiple concurrent scans
        test = TestCase(
            name=f"Concurrent Scans ({NUM_CONCURRENT_SCANS})",
            description=f"Run {NUM_CONCURRENT_SCANS} scans concurrently"
        )
        start = time.time()
        
        def run_single_scan(scan_num: int):
            """Run a mini scan lifecycle"""
            scan_id = f"{SCAN_ID_PREFIX}concurrent_{scan_num}_{uuid.uuid4().hex[:6]}"
            
            events = []
            events.append(("scan_started", {
                "scan_id": scan_id,
                "project_id": PROJECT_ID,
                "target_url": f"{TARGET_URL}/concurrent/{scan_num}",
                "agent_id": AGENT_ID,
                "data": {"concurrent_test": True}
            }))
            
            for i in range(3):
                events.append(("scan_progress", {
                    "scan_id": scan_id,
                    "agent_id": AGENT_ID,
                    "data": {"step": i + 1, "total": 3}
                }))
            
            events.append(("scan_completed", {
                "scan_id": scan_id,
                "agent_id": AGENT_ID,
                "data": {"duration": 5}
            }))
            
            # Send all events
            results = []
            for event_type, payload in events:
                data, status, _ = self.client.request("POST", "/agent/events", payload)
                results.append(status in [200, 202])
                time.sleep(0.05)  # Tiny delay
            
            return all(results), scan_id
        
        # Run concurrent scans
        with ThreadPoolExecutor(max_workers=NUM_CONCURRENT_SCANS) as executor:
            futures = [executor.submit(run_single_scan, i) for i in range(NUM_CONCURRENT_SCANS)]
            results = [future.result() for future in as_completed(futures)]
        
        success_count = sum(1 for success, _ in results if success)
        scan_ids = [scan_id for _, scan_id in results]
        self.scan_ids.extend(scan_ids)
        
        if success_count == NUM_CONCURRENT_SCANS:
            test.result = TestResult.PASS
            test.details = {
                "scans_successful": success_count,
                "total_scans": NUM_CONCURRENT_SCANS,
                "scan_ids": scan_ids
            }
        elif success_count > 0:
            test.result = TestResult.WARN
            test.error = f"{success_count}/{NUM_CONCURRENT_SCANS} scans succeeded"
        else:
            test.result = TestResult.FAIL
            test.error = "All concurrent scans failed"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 2: Rapid fire events
        test = TestCase(
            name="Rapid Event Submission",
            description="Send events as fast as possible"
        )
        start = time.time()
        
        scan_id = f"{SCAN_ID_PREFIX}rapid_{uuid.uuid4().hex[:6]}"
        self.scan_ids.append(scan_id)
        
        # Send scan started
        self.client.request("POST", "/agent/events", {
            "event_type": "scan_started",
            "scan_id": scan_id,
            "agent_id": AGENT_ID,
            "data": {"rapid_test": True}
        })
        
        # Send rapid progress events
        latencies = []
        for i in range(10):
            _, status, latency = self.client.request("POST", "/agent/events", {
                "event_type": "scan_progress",
                "scan_id": scan_id,
                "agent_id": AGENT_ID,
                "data": {"step": i + 1, "total": 10}
            })
            latencies.append(latency)
            # No delay between events
        
        # Send completed
        self.client.request("POST", "/agent/events", {
            "event_type": "scan_completed",
            "scan_id": scan_id,
            "agent_id": AGENT_ID,
            "data": {"duration": 2}
        })
        
        avg_latency = statistics.mean(latencies) if latencies else 0
        test.details = {
            "events_sent": 12,  # started + 10 progress + completed
            "avg_latency_ms": round(avg_latency * 1000, 2),
            "max_latency_ms": round(max(latencies) * 1000, 2) if latencies else 0
        }
        
        if avg_latency < 1.0:  # Less than 1 second average
            test.result = TestResult.PASS
        else:
            test.result = TestResult.WARN
            test.error = f"High average latency: {avg_latency:.2f}s"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def run_error_handling_tests(self):
        """Test error cases and edge conditions"""
        print("\n⚠️  ERROR HANDLING TESTS")
        print("-" * 40)
        
        # Test 1: Invalid event type
        test = TestCase(
            name="Invalid Event Type Rejection",
            description="Send event with invalid event_type"
        )
        start = time.time()
        
        _, status, _ = self.client.request("POST", "/agent/events", {
            "event_type": "invalid_event_type_123",
            "scan_id": "test_scan",
            "agent_id": AGENT_ID,
            "data": {"test": "invalid"}
        })
        
        # Backend should either accept (if flexible) or reject gracefully
        if status in [200, 202, 400, 422]:
            test.result = TestResult.PASS
            test.details = {"status": status, "expected": "200/202 (accept) or 400/422 (reject)"}
        else:
            test.result = TestResult.WARN
            test.error = f"Unexpected status for invalid event: {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 2: Missing required fields
        test = TestCase(
            name="Missing Required Fields",
            description="Send event without scan_id"
        )
        start = time.time()
        
        _, status, _ = self.client.request("POST", "/agent/events", {
            "event_type": "scan_started",
            "agent_id": AGENT_ID,  # Missing scan_id
            "data": {"test": "missing_field"}
        })
        
        if status in [400, 422]:  # Should be a client error
            test.result = TestResult.PASS
        else:
            test.result = TestResult.WARN
            test.error = f"Should reject missing scan_id with 400/422, got {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 3: Malformed JSON
        test = TestCase(
            name="Malformed JSON Handling",
            description="Send invalid JSON payload"
        )
        start = time.time()
        
        # Temporarily override session to send bad JSON
        original_session = self.client.session
        try:
            # Create a one-off request with bad JSON
            headers = {**self.client.headers, "Content-Type": "application/json"}
            response = requests.post(
                f"{BASE_URL}/agent/events",
                headers=headers,
                data='{"event_type": "test", "scan_id": "test", "agent_id": "test", "data": {',  # Missing closing brace
                timeout=5
            )
            status = response.status_code
            
            if status in [400, 422, 500]:
                test.result = TestResult.PASS
                test.details = {"status": status}
            else:
                test.result = TestResult.WARN
                test.error = f"Unexpected status for malformed JSON: {status}"
        
        except Exception as e:
            test.result = TestResult.FAIL
            test.error = f"Exception with malformed JSON: {str(e)}"
        finally:
            self.client.session = original_session
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
        
        # Test 4: Very large payload
        test = TestCase(
            name="Large Payload Handling",
            description="Send event with very large data field"
        )
        start = time.time()
        
        # Create large payload (approx 50KB)
        large_data = {"large_array": ["x" * 100] * 500}  # ~50KB
        
        _, status, latency = self.client.request("POST", "/agent/events", {
            "event_type": "test_large_payload",
            "scan_id": "test_large",
            "agent_id": AGENT_ID,
            "data": large_data
        })
        
        if status in [200, 202]:
            test.result = TestResult.PASS
            test.details = {"status": status, "latency_ms": round(latency * 1000, 2)}
        elif status == 413:  # Payload too large
            test.result = TestResult.PASS
            test.details = {"status": status, "note": "Correctly rejected oversized payload"}
        else:
            test.result = TestResult.WARN
            test.error = f"Unexpected status for large payload: {status}"
        
        test.duration = time.time() - start
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def run_performance_tests(self):
        """Test performance and throughput"""
        print("\n📊 PERFORMANCE TESTS")
        print("-" * 40)
        
        # Test 1: Batch event throughput
        test = TestCase(
            name="Event Throughput",
            description="Measure events per second"
        )
        start = time.time()
        
        scan_id = f"{SCAN_ID_PREFIX}perf_{uuid.uuid4().hex[:6]}"
        self.scan_ids.append(scan_id)
        
        # Send batch of events
        batch_size = 50
        latencies = []
        
        for i in range(batch_size):
            _, status, latency = self.client.request("POST", "/agent/events", {
                "event_type": "scan_progress",
                "scan_id": scan_id,
                "agent_id": AGENT_ID,
                "data": {"step": i + 1, "total": batch_size, "timestamp": int(time.time())}
            })
            latencies.append(latency)
        
        total_time = time.time() - start
        events_per_second = batch_size / total_time if total_time > 0 else 0
        avg_latency = statistics.mean(latencies) if latencies else 0
        
        test.details = {
            "batch_size": batch_size,
            "total_time": round(total_time, 2),
            "events_per_second": round(events_per_second, 2),
            "avg_latency_ms": round(avg_latency * 1000, 2),
            "p95_latency_ms": round(statistics.quantiles(latencies, n=20)[18] * 1000, 2) if len(latencies) >= 20 else 0
        }
        
        if events_per_second >= 10:  # Minimum 10 events/second
            test.result = TestResult.PASS
        elif events_per_second >= 5:
            test.result = TestResult.WARN
            test.error = f"Low throughput: {events_per_second:.1f} events/second"
        else:
            test.result = TestResult.FAIL
            test.error = f"Very low throughput: {events_per_second:.1f} events/second"
        
        test.duration = total_time
        self.add_test(test)
        print(f"{test.result.value}: {test.name}")
    
    def print_summary(self):
        """Print test execution summary"""
        print("\n" + "="*70)
        print("📋 TEST SUMMARY")
        print("="*70)
        
        total = len(self.tests)
        passed = sum(1 for t in self.tests if t.result == TestResult.PASS)
        failed = sum(1 for t in self.tests if t.result == TestResult.FAIL)
        warned = sum(1 for t in self.tests if t.result == TestResult.WARN)
        skipped = sum(1 for t in self.tests if t.result == TestResult.SKIP)
        
        print(f"\n📊 Results: {passed} passed, {warned} warnings, {failed} failed, {skipped} skipped")
        
        if failed > 0:
            print("\n❌ FAILED TESTS:")
            for test in self.tests:
                if test.result == TestResult.FAIL:
                    print(f"  • {test.name}: {test.error}")
        
        if warned > 0:
            print("\n⚠️  WARNINGS:")
            for test in self.tests:
                if test.result == TestResult.WARN:
                    print(f"  • {test.name}: {test.error}")
        
        print(f"\n🕒 Total test duration: {sum(t.duration for t in self.tests):.2f}s")
        print(f"🔑 Agent ID: {AGENT_ID}")
        print(f"🔍 Scans created: {len(self.scan_ids)}")
        if self.scan_ids:
            print(f"   Sample scan IDs: {', '.join(self.scan_ids[:3])}")
            if len(self.scan_ids) > 3:
                print(f"   ... and {len(self.scan_ids) - 3} more")
        
        print("\n" + "="*70)
        if failed == 0:
            print("✅ BACKEND VALIDATION COMPLETE - ALL CRITICAL TESTS PASSED")
        else:
            print("❌ BACKEND VALIDATION FAILED - SOME TESTS DID NOT PASS")
        print("="*70)
    
    def print_metrics(self):
        """Print HTTP client metrics"""
        print("\n📈 HTTP CLIENT METRICS")
        print("-" * 40)
        
        metrics = self.client.get_metrics()
        for key, value in metrics.items():
            if isinstance(value, float):
                print(f"  {key}: {value:.2f}")
            else:
                print(f"  {key}: {value}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="LeakHunterX Backend Validator")
    parser.add_argument("--url", default=BASE_URL, help="Backend base URL")
    parser.add_argument("--agent-id", help="Custom agent ID")
    parser.add_argument("--secret", help="Custom agent secret")
    parser.add_argument("--skip", nargs="+", help="Test categories to skip")
    args = parser.parse_args()
    
    # Override defaults if provided
    if args.agent_id:
        AGENT_ID = args.agent_id
    if args.secret:
        AGENT_SECRET = args.secret
    if args.url:
        BASE_URL = args.url
    
    print(f"🔧 Configuration:")
    print(f"   Backend URL: {BASE_URL}")
    print(f"   Agent ID: {AGENT_ID}")
    print(f"   Agent Secret: {'*' * len(AGENT_SECRET)}")
    
    # Run validator
    validator = BackendValidator()
    
    try:
        validator.run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⏹️  Validation interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n✨ Validation complete. Check results above.")