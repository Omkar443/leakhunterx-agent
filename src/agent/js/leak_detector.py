"""
Enterprise-Grade Leak Detector with Advanced Pattern Recognition
Maintains 100% compatibility with existing code

LEGACY WARNING: EnterpriseLeakDetector is stateful and meant for backward compatibility.
For SaaS/event-driven use, use SecretScanner class instead.
"""

import re
import math
import hashlib
import time
from typing import List, Dict, Any

# ─────────────────────────────────────────────
# 📦 PACKAGE-RELATIVE IMPORT (CRITICAL FIX)
# ─────────────────────────────────────────────

from ..utils.events import emit_event


class EnterpriseLeakDetector:
    """
    LEGACY Enterprise Leak Detector (stateful, for backward compatibility only)

    WARNING: This class maintains internal state (caches, counters, dedup sets).
    For stateless, event-driven scanning, use SecretScanner class instead.
    """

    # Enhanced regex patterns with validation functions
    PATTERNS = {
        # Cloud Keys - Enhanced patterns
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "confidence": 0.95,
            "validation": lambda x: len(x) == 20 and x.startswith('AKIA'),
            "severity": "HIGH"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws[^'\"\n]{0,20}?['\"\s:=]([A-Za-z0-9/+=]{40})",
            "confidence": 0.85,
            "validation": lambda x: len(x) == 40,
            "severity": "CRITICAL"
        },

        # Google Cloud - Enhanced patterns
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "confidence": 0.90,
            "validation": lambda x: len(x) >= 39 and x.startswith('AIza'),
            "severity": "HIGH"
        },
        "google_oauth_token": {
            "pattern": r"ya29\.[0-9A-Za-z\-_]+",
            "confidence": 0.80,
            "validation": lambda x: x.startswith('ya29.'),
            "severity": "MEDIUM"
        },

        # API Keys - Enhanced patterns
        "generic_api_key": {
            "pattern": r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"\s:=]+([A-Za-z0-9\-_.=]{20,})",
            "confidence": 0.70,
            "validation": lambda x: len(x) >= 20,
            "severity": "MEDIUM"
        },
        "bearer_token": {
            "pattern": r"(?i)bearer[\s]+([A-Za-z0-9\-_.=]{50,})",
            "confidence": 0.75,
            "validation": lambda x: len(x) >= 50,
            "severity": "MEDIUM"
        },

        # Authentication - Enhanced patterns
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "confidence": 0.80,
            "validation": lambda x: len(x.split('.')) == 3,
            "severity": "MEDIUM"
        },
        "basic_auth": {
            "pattern": r"(?i)basic[\s]+([A-Za-z0-9+/=]{20,})",
            "confidence": 0.65,
            "validation": lambda x: len(x) >= 20,
            "severity": "MEDIUM"
        },

        # Service-specific keys - Enhanced patterns
        "stripe_key": {
            "pattern": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24}",
            "confidence": 0.95,
            "validation": lambda x: x.startswith(('sk_', 'pk_')),
            "severity": "HIGH"
        },
        "twilio_key": {
            "pattern": r"SK[0-9a-fA-F]{32}",
            "confidence": 0.90,
            "validation": lambda x: len(x) == 34 and x.startswith('SK'),
            "severity": "HIGH"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "confidence": 0.85,
            "validation": lambda x: x.startswith(('xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-')),
            "severity": "MEDIUM"
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36}",
            "confidence": 0.90,
            "validation": lambda x: x.startswith(('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')),
            "severity": "HIGH"
        },
        "mailgun_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "confidence": 0.80,
            "validation": lambda x: len(x) == 36 and x.startswith('key-'),
            "severity": "MEDIUM"
        },

        # Database connections - Enhanced patterns
        "mongodb_uri": {
            "pattern": r"mongodb(\+srv)?://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'mongodb' in x,
            "severity": "HIGH"
        },
        "mysql_connection": {
            "pattern": r"mysql://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'mysql://' in x,
            "severity": "HIGH"
        },
        "postgres_connection": {
            "pattern": r"postgres(ql)?://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'postgres' in x,
            "severity": "HIGH"
        },
        "redis_connection": {
            "pattern": r"redis://[^\s\"']+",
            "confidence": 0.85,
            "validation": lambda x: 'redis://' in x,
            "severity": "HIGH"
        },

        # Cloud storage - Enhanced patterns
        "s3_bucket": {
            "pattern": r"s3://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('s3://'),
            "severity": "MEDIUM"
        },
        "s3_url": {
            "pattern": r"https?://[a-z0-9\-\.]+\.s3\.(?:[a-z0-9\-\.]+)?amazonaws\.com",
            "confidence": 0.80,
            "validation": lambda x: '.s3.' in x and 'amazonaws.com' in x,
            "severity": "MEDIUM"
        },
        "google_storage": {
            "pattern": r"gs://[a-z0-9\-\.]+",
            "confidence": 0.75,
            "validation": lambda x: x.startswith('gs://'),
            "severity": "MEDIUM"
        },
        "azure_storage": {
            "pattern": r"https?://[a-z0-9]+\.blob\.core\.windows\.net",
            "confidence": 0.80,
            "validation": lambda x: '.blob.core.windows.net' in x,
            "severity": "MEDIUM"
        },

        # Email/password combos - Enhanced patterns
        "email_password": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[:|,|\s]+[^\s\"']+",
            "confidence": 0.60,
            "validation": lambda x: '@' in x and '.' in x,
            "severity": "HIGH"
        },

        # Internal endpoints - Enhanced patterns
        "admin_endpoint": {
            "pattern": r"(?i)(admin|internal|private|staging|dev|test)[^\"'\s]{0,30}",
            "confidence": 0.50,
            "validation": lambda x: len(x) > 5,
            "severity": "LOW"
        },
    }

    def __init__(self, aggressive: bool = False):
        # Copy class patterns to instance to prevent global mutation
        self.PATTERNS = dict(self.PATTERNS)

        self.aggressive = aggressive
        self.performance_metrics = {
            'total_checks': 0,
            'patterns_matched': 0,
            'high_confidence_finds': 0,
            'processing_time': 0
        }
        self.seen_leaks = set()  # Deduplication cache

        if aggressive:
            self._enable_aggressive_patterns()

    def _enable_aggressive_patterns(self):
        """Enable more aggressive detection patterns"""
        aggressive_patterns = {
            "private_ip": {
                "pattern": r"(?i)(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}",
                "confidence": 0.95,
                "validation": lambda x: self._validate_ip_address(x),
                "severity": "MEDIUM"
            },
            "credit_card": {
                "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
                "confidence": 0.90,
                "validation": lambda x: self._validate_credit_card(x),
                "severity": "HIGH"
            },
            "ssh_private_key": {
                "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                "confidence": 0.98,
                "validation": lambda x: 'PRIVATE KEY' in x,
                "severity": "CRITICAL"
            },
            "api_endpoint_leak": {
                "pattern": r"(?i)(endpoint|url|uri)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\'][^\"\']*(key|secret|token)[\"\']?\s*[:=]\s*[\"\'][^\"\']+[\"\']",
                "confidence": 0.70,
                "validation": lambda x: len(x) > 20,
                "severity": "MEDIUM"
            }
        }
        self.PATTERNS.update(aggressive_patterns)

    def _validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    def _validate_credit_card(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm"""
        try:
            digits = [int(d) for d in str(number) if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False

            # Luhn algorithm
            checksum = 0
            parity = len(digits) % 2
            for i, digit in enumerate(digits):
                if (i % 2) == parity:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return (checksum % 10) == 0
        except (ValueError, TypeError):
            return False

    def entropy(self, text: str) -> float:
        """Enhanced Shannon entropy calculation with caching"""
        if not text:
            return 0.0

        text = str(text)

        # Simple cache for performance
        cache_key = hashlib.sha256(text.encode()).hexdigest()
        if hasattr(self, '_entropy_cache') and cache_key in self._entropy_cache:
            return self._entropy_cache[cache_key]

        entropy_val = 0.0
        text_length = len(text)

        if text_length == 0:
            return 0.0

        for char in set(text):
            p_x = float(text.count(char)) / text_length
            if p_x > 0:
                entropy_val += - p_x * math.log2(p_x)

        # Cache the result
        if not hasattr(self, '_entropy_cache'):
            self._entropy_cache = {}
        self._entropy_cache[cache_key] = entropy_val

        return entropy_val

    def _generate_leak_signature(self, leak_type: str, value: str) -> str:
        """Generate unique signature for leak deduplication"""
        return hashlib.sha256(f"{leak_type}:{value}".encode()).hexdigest()[:32]

    def _extract_context(self, content: str, match: str, position: int) -> str:
        """Extract context around the matched leak"""
        try:
            start = max(0, position - 50)
            end = min(len(content), position + len(match) + 50)
            context = content[start:end]

            # Clean and normalize context
            context = re.sub(r'\s+', ' ', context)
            return context.strip()
        except Exception:
            return ""

    def _calculate_risk_score(self, leak_type: str, entropy: float, confidence: float) -> float:
        """Calculate comprehensive risk score"""
        base_risk = {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.5,
            "LOW": 0.3
        }.get(self.PATTERNS[leak_type]["severity"], 0.3)

        entropy_factor = min(entropy / 8.0, 1.0)  # Normalize entropy
        confidence_factor = confidence

        return (base_risk * 0.4) + (entropy_factor * 0.3) + (confidence_factor * 0.3)

    def check_content(self, content: str) -> List[Dict[str, Any]]:
        """
        Enterprise-grade content checking with advanced features
        Maintains 100% compatibility with existing code

        WARNING: This method maintains internal state (caches, counters).
        For stateless scanning, use SecretScanner.scan() instead.
        """
        start_time = time.time()
        findings = []

        if not content or not isinstance(content, str):
            self.performance_metrics['total_checks'] += 1
            return findings

        for name, config in self.PATTERNS.items():
            try:
                pattern = config["pattern"]
                base_confidence = config["confidence"]
                validation_func = config["validation"]
                base_severity = config["severity"]

                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                for match in matches:
                    # Handle group matches
                    if match.groups():
                        leak_value = next((g for g in match.groups() if g), match.group(0))
                    else:
                        leak_value = match.group(0)

                    if not leak_value or len(leak_value) < 5:
                        continue

                    # Deduplication check
                    leak_signature = self._generate_leak_signature(name, leak_value)
                    if leak_signature in self.seen_leaks:
                        continue
                    self.seen_leaks.add(leak_signature)

                    # Enhanced validation
                    is_valid = validation_func(leak_value)
                    validation_status = "validated" if is_valid else "suspicious"

                    # Calculate enhanced metrics
                    ent = self.entropy(leak_value)
                    confidence_score = base_confidence if is_valid else base_confidence * 0.6

                    # Context extraction
                    context = self._extract_context(content, leak_value, match.start())

                    # Risk scoring
                    risk_score = self._calculate_risk_score(name, ent, confidence_score)

                    # Dynamic severity adjustment
                    final_severity = self._adjust_severity(base_severity, ent, risk_score)

                    finding = {
                        "type": name,
                        "value": leak_value[:100],  # Truncate for safety
                        "severity": final_severity,
                        "entropy": round(ent, 2),
                        "suspicious": ent > 3.5,
                        "confidence": round(confidence_score, 2),
                        "context": context,
                        "line_number": content[:match.start()].count('\n') + 1,
                        "risk_score": round(risk_score, 2),
                        "validation_status": validation_status
                    }

                    findings.append(finding)
                    self.performance_metrics['patterns_matched'] += 1

                    if confidence_score > 0.8:
                        self.performance_metrics['high_confidence_finds'] += 1

            except Exception:
                continue

        # Remove near-duplicates based on value similarity
        unique_findings = self._deduplicate_findings(findings)

        # Update performance metrics
        self.performance_metrics['total_checks'] += 1
        self.performance_metrics['processing_time'] += time.time() - start_time

        return unique_findings

    def _adjust_severity(self, base_severity: str, entropy: float, risk_score: float) -> str:
        """Adjust severity based on entropy and risk score"""
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        base_level = severity_map.get(base_severity, 0)

        # Increase severity for high entropy
        if entropy > 4.0:
            base_level = min(base_level + 1, 3)

        # Increase severity for high risk
        if risk_score > 0.8:
            base_level = min(base_level + 1, 3)

        # Decrease severity for low risk
        if risk_score < 0.3:
            base_level = max(base_level - 1, 0)

        # Map back to string
        reverse_map = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
        return reverse_map.get(base_level, "LOW")

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Advanced deduplication of findings"""
        unique_findings = []
        seen_values = set()

        for finding in findings:
            # Create a normalized version for comparison
            normalized_value = finding["value"].lower().strip()

            # Skip if we've seen this exact value
            if normalized_value in seen_values:
                continue

            # Skip if this is a subset of another finding
            is_subset = any(
                normalized_value in seen_val and normalized_value != seen_val
                for seen_val in seen_values
            )

            if not is_subset:
                seen_values.add(normalized_value)
                unique_findings.append(finding)

        return unique_findings

    def compute_severity(self, leak_type: str, entropy: float) -> str:
        """Backward compatibility method"""
        base_severity = self.PATTERNS.get(leak_type, {}).get("severity", "LOW")
        return self._adjust_severity(base_severity, entropy, 0.5)

    def group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Enhanced grouping by severity with sorting"""
        grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in grouped:
                grouped[severity].append(finding)

        # Sort each group by risk score (descending)
        for severity in grouped:
            grouped[severity].sort(key=lambda x: x.get("risk_score", 0), reverse=True)

        return grouped

    def get_stats(self, findings: List[Dict]) -> Dict[str, Any]:
        """Enhanced statistics with performance metrics"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        risk_scores = []

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1
            risk_scores.append(finding.get("risk_score", 0))

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "suspicious_count": sum(1 for f in findings if f.get("suspicious", False)),
            "avg_risk_score": round(avg_risk, 2),
            "performance_metrics": self.performance_metrics.copy(),
            "high_confidence_findings": sum(1 for f in findings if f.get("confidence", 0) > 0.8)
        }

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics"""
        avg_processing_time = (
            self.performance_metrics['processing_time'] /
            self.performance_metrics['total_checks']
            if self.performance_metrics['total_checks'] > 0 else 0
        )

        return {
            **self.performance_metrics,
            'avg_processing_time_ms': round(avg_processing_time * 1000, 2),
            'patterns_configured': len(self.PATTERNS),
            'unique_leaks_detected': len(self.seen_leaks)
        }

    def reset_metrics(self):
        """Reset performance metrics for new scan"""
        self.performance_metrics = {
            'total_checks': 0,
            'patterns_matched': 0,
            'high_confidence_finds': 0,
            'processing_time': 0
        }
        self.seen_leaks.clear()
        if hasattr(self, '_entropy_cache'):
            self._entropy_cache.clear()


class SecretScanner:
    """
    Stateless, event-driven secret scanner for SaaS/Agent architecture.

    Uses same detection logic as EnterpriseLeakDetector but:
    1. No internal state (all state in context.shared_state)
    2. Emits events via context.event_emitter
    3. Stateless and resettable per scan
    4. No logging inside logic
    """

    def __init__(self, aggressive: bool = False):
        # Store configuration only, no state
        self.aggressive = aggressive

    async def scan(self, content: str, source_url: str, context) -> None:
        """
        Scan content for secrets and emit events.

        CRITICAL: Uses EXACT same detection logic as EnterpriseLeakDetector.
        Only architectural changes:
        1. Emits events via context.event_emitter
        2. Uses context.shared_state for all state
        3. Stateless and resettable per scan
        4. No logging inside logic

        Args:
            content: Content to scan for secrets
            source_url: URL where content came from
            context: ExtractorContext instance for state/events
        """
        if not content or not isinstance(content, str):
            if "total_checks" in context.shared_state["metrics"]:
                context.shared_state["metrics"]["total_checks"] += 1
            return

        # Create fresh, stateless detector instance for this scan
        detector = EnterpriseLeakDetector(aggressive=self.aggressive)

        # Share entropy cache with context (optimization only)
        detector._entropy_cache = context.shared_state["entropy_cache"]

        # Disable detector's internal dedup (use context only)
        detector.seen_leaks = set()

        # Run detection using stateless instance
        findings = detector.check_content(content)

        # Copy metrics ONCE after scan (not per finding)
        for key in ['total_checks', 'patterns_matched', 'high_confidence_finds', 'processing_time']:
            if key in detector.performance_metrics and key in context.shared_state["metrics"]:
                context.shared_state["metrics"][key] = detector.performance_metrics[key]

        # Emit events for each finding with context-based dedup only
        for finding in findings:
            # Deduplication using ONLY context.shared_state
            leak_signature = detector._generate_leak_signature(
                finding["type"],
                finding["value"]
            )

            # 🔒 FIX #1: HARD TYPE GUARD FOR SERIALIZATION ISSUES
            seen = context.shared_state.get("seen_leaks")

            # 🔒 ENSURE seen_leaks is always a set (handles JSON serialization edge cases)
            if not isinstance(seen, set):
                seen = set(seen or [])
                context.shared_state["seen_leaks"] = seen

            if leak_signature in seen:
                continue

            seen.add(leak_signature)

            # 🔒 CANONICAL secret_found EVENT (BACKEND CONTRACT COMPLIANT)
            fingerprint = detector._generate_leak_signature(
                finding["type"],
                finding["value"]
            )

            await emit_event(
                context,
                event_type="secret_found",
                data={
                    # REQUIRED FIELDS (used by DB + reports)
                    "type": finding["type"].replace("_", " ").title(),
                    "category": "Secrets",
                    "severity": finding["severity"].lower(),
                    "confidence": float(finding["confidence"]),
                    "raw_value": finding["value"],
                    "fingerprint": fingerprint,

                    # LOCATION
                    "file_path": source_url,
                    "line_number": finding.get("line_number"),

                    # OPTIONAL (safe extras)
                    "entropy": finding.get("entropy"),
                    "risk_score": finding.get("risk_score"),
                    "validation_status": finding.get("validation_status"),
                }
            )


# Backward compatibility - original class name (LEGACY)
LeakDetector = EnterpriseLeakDetector