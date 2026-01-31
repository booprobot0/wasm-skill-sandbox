"""
Skill Scanner - Security analysis for agent skills

This module scans Python code for common security issues that could indicate
malicious or dangerous skill code. It runs as a pure WASM component with
NO network or filesystem access.

Scan Categories:
- API key exfiltration (environment variable access, .env reading)
- Suspicious network targets (webhook.site, pastebin, etc.)
- Credential access (SSH keys, tokens, passwords)
- Obfuscated code (base64 decode + exec, eval usage)
"""

import re
import json
from dataclasses import dataclass
from typing import List, Dict, Any

# Import the generated bindings
import scanner_component.exports


@dataclass
class Finding:
    """A security finding from the scan"""
    category: str
    severity: str  # critical, high, medium, low
    pattern: str
    line: int
    context: str
    description: str


class SkillScanner:
    """Scans skill code for security issues"""

    # Severity weights for safety score calculation
    SEVERITY_WEIGHTS = {
        "critical": 0.4,
        "high": 0.25,
        "medium": 0.1,
        "low": 0.05,
    }

    def __init__(self):
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Compile all security patterns"""
        return {
            "api_exfiltration": [
                {
                    "pattern": re.compile(r"os\.environ\s*\[|os\.environ\.get\s*\(|os\.getenv\s*\(", re.IGNORECASE),
                    "severity": "high",
                    "description": "Environment variable access - potential API key exfiltration",
                },
                {
                    "pattern": re.compile(r"dotenv|load_dotenv|\.env", re.IGNORECASE),
                    "severity": "high",
                    "description": "Dotenv usage - may read sensitive environment files",
                },
                {
                    "pattern": re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET_KEY|AWS_SECRET", re.IGNORECASE),
                    "severity": "critical",
                    "description": "Direct reference to API key variable names",
                },
            ],
            "suspicious_network": [
                {
                    "pattern": re.compile(r"webhook\.site|pipedream\.net|requestbin", re.IGNORECASE),
                    "severity": "critical",
                    "description": "Known data exfiltration endpoint",
                },
                {
                    "pattern": re.compile(r"pastebin\.com|hastebin\.com|paste\.ee", re.IGNORECASE),
                    "severity": "high",
                    "description": "Paste site - potential data leak destination",
                },
                {
                    "pattern": re.compile(r"ngrok\.io|localtunnel\.me|serveo\.net", re.IGNORECASE),
                    "severity": "high",
                    "description": "Tunnel service - may exfiltrate to attacker-controlled endpoint",
                },
                {
                    "pattern": re.compile(r"discord\.com/api/webhooks|slack\.com/api|telegram\.org/bot", re.IGNORECASE),
                    "severity": "medium",
                    "description": "Messaging webhook - potential exfiltration channel",
                },
            ],
            "credential_access": [
                {
                    "pattern": re.compile(r"~/.ssh|/\.ssh/|id_rsa|id_ed25519|authorized_keys", re.IGNORECASE),
                    "severity": "critical",
                    "description": "SSH key access attempt",
                },
                {
                    "pattern": re.compile(r"\.aws/credentials|\.aws/config", re.IGNORECASE),
                    "severity": "critical",
                    "description": "AWS credentials file access",
                },
                {
                    "pattern": re.compile(r"\.netrc|\.pgpass|\.my\.cnf", re.IGNORECASE),
                    "severity": "high",
                    "description": "Database/network credentials file access",
                },
                {
                    "pattern": re.compile(r"/etc/passwd|/etc/shadow|/etc/sudoers", re.IGNORECASE),
                    "severity": "critical",
                    "description": "System authentication file access",
                },
                {
                    "pattern": re.compile(r"keychain|keyring|credential_manager|secrets\.json", re.IGNORECASE),
                    "severity": "high",
                    "description": "System keychain/credential manager access",
                },
            ],
            "obfuscated_code": [
                {
                    "pattern": re.compile(r"base64\.b64decode\s*\([^)]+\)\s*\)?\s*\.decode|b64decode.*exec|b64decode.*eval", re.IGNORECASE),
                    "severity": "critical",
                    "description": "Base64 decode with execution - likely obfuscated malicious code",
                },
                {
                    "pattern": re.compile(r"exec\s*\(\s*(base64|codecs|zlib|gzip)", re.IGNORECASE),
                    "severity": "critical",
                    "description": "Execution of encoded/compressed payload",
                },
                {
                    "pattern": re.compile(r"eval\s*\(", re.IGNORECASE),
                    "severity": "high",
                    "description": "Eval usage - can execute arbitrary code",
                },
                {
                    "pattern": re.compile(r"exec\s*\(", re.IGNORECASE),
                    "severity": "high",
                    "description": "Exec usage - can execute arbitrary code",
                },
                {
                    "pattern": re.compile(r"compile\s*\([^)]+,[^)]*['\"]exec['\"]", re.IGNORECASE),
                    "severity": "high",
                    "description": "Dynamic code compilation",
                },
                {
                    "pattern": re.compile(r"__import__\s*\(", re.IGNORECASE),
                    "severity": "medium",
                    "description": "Dynamic import - may load unexpected modules",
                },
                {
                    "pattern": re.compile(r"getattr\s*\([^,]+,\s*['\"][^'\"]+['\"]", re.IGNORECASE),
                    "severity": "low",
                    "description": "Dynamic attribute access - review for safety",
                },
            ],
            "dangerous_imports": [
                {
                    "pattern": re.compile(r"import\s+subprocess|from\s+subprocess", re.IGNORECASE),
                    "severity": "medium",
                    "description": "Subprocess import - can execute shell commands",
                },
                {
                    "pattern": re.compile(r"import\s+socket|from\s+socket", re.IGNORECASE),
                    "severity": "medium",
                    "description": "Socket import - low-level network access",
                },
                {
                    "pattern": re.compile(r"import\s+ctypes|from\s+ctypes", re.IGNORECASE),
                    "severity": "high",
                    "description": "Ctypes import - can call arbitrary C functions",
                },
                {
                    "pattern": re.compile(r"import\s+pickle|from\s+pickle", re.IGNORECASE),
                    "severity": "high",
                    "description": "Pickle import - deserialization can execute arbitrary code",
                },
            ],
        }

    def scan(self, code: str) -> Dict[str, Any]:
        """
        Scan code for security issues

        Returns a dict with:
        - findings: list of security issues found
        - safety_score: float 0-1 (1 = safe, 0 = dangerous)
        - summary: human-readable summary
        """
        findings: List[Finding] = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            for category, patterns in self.patterns.items():
                for pattern_info in patterns:
                    if pattern_info["pattern"].search(line):
                        # Get context (line content, trimmed)
                        context = line.strip()[:100]
                        if len(line.strip()) > 100:
                            context += "..."

                        findings.append(Finding(
                            category=category,
                            severity=pattern_info["severity"],
                            pattern=pattern_info["pattern"].pattern[:50],
                            line=line_num,
                            context=context,
                            description=pattern_info["description"],
                        ))

        # Calculate safety score
        safety_score = self._calculate_safety_score(findings)

        # Generate summary
        summary = self._generate_summary(findings, safety_score)

        return {
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "line": f.line,
                    "context": f.context,
                    "description": f.description,
                }
                for f in findings
            ],
            "safety_score": round(safety_score, 2),
            "summary": summary,
            "total_findings": len(findings),
            "findings_by_severity": {
                "critical": len([f for f in findings if f.severity == "critical"]),
                "high": len([f for f in findings if f.severity == "high"]),
                "medium": len([f for f in findings if f.severity == "medium"]),
                "low": len([f for f in findings if f.severity == "low"]),
            },
        }

    def _calculate_safety_score(self, findings: List[Finding]) -> float:
        """Calculate safety score from 0 (dangerous) to 1 (safe)"""
        if not findings:
            return 1.0

        # Calculate penalty based on severity weights
        penalty = sum(
            self.SEVERITY_WEIGHTS.get(f.severity, 0.1)
            for f in findings
        )

        # Clamp to 0-1 range
        return max(0.0, min(1.0, 1.0 - penalty))

    def _generate_summary(self, findings: List[Finding], safety_score: float) -> str:
        """Generate human-readable summary"""
        if not findings:
            return "No security issues detected. Code appears safe."

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        parts = []
        if severity_counts.get("critical", 0) > 0:
            parts.append(f"{severity_counts['critical']} CRITICAL")
        if severity_counts.get("high", 0) > 0:
            parts.append(f"{severity_counts['high']} high")
        if severity_counts.get("medium", 0) > 0:
            parts.append(f"{severity_counts['medium']} medium")
        if severity_counts.get("low", 0) > 0:
            parts.append(f"{severity_counts['low']} low")

        severity_summary = ", ".join(parts)

        if safety_score < 0.3:
            risk_level = "DANGEROUS"
        elif safety_score < 0.6:
            risk_level = "RISKY"
        elif safety_score < 0.8:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "MINOR CONCERNS"

        # Get unique categories
        categories = list(set(f.category for f in findings))
        category_str = ", ".join(c.replace("_", " ") for c in categories)

        return f"{risk_level}: Found {len(findings)} issues ({severity_summary}). Categories: {category_str}."


# Global scanner instance
_scanner = SkillScanner()


class Scanner(scanner_component.exports.Scanner):
    """Implementation of the scanner interface for WASM component"""

    def scan_code(self, code: str) -> str:
        """Scan code and return JSON results"""
        result = _scanner.scan(code)
        return json.dumps(result, indent=2)
