"""High-confidence credential and secret detector."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sensitiveguard.detector.regex_detector import RegexDetector, RegexPattern
from sensitiveguard.models import Severity


DEFAULT_SECRET_PATTERNS: tuple[RegexPattern, ...] = (
    RegexPattern(
        "PRIVATE_KEY",
        r"(?P<value>-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        1.0,
        Severity.CRITICAL,
        flags=re.IGNORECASE | re.DOTALL,
    ),
    RegexPattern(
        "JWT",
        r"(?<![A-Z0-9_-])(?P<value>eyJ[A-Z0-9_-]{5,}\.[A-Z0-9_-]{5,}\.[A-Z0-9_-]{5,})(?![A-Z0-9_-])",
        0.99,
        Severity.CRITICAL,
    ),
    RegexPattern(
        "CLOUD_SECRET",
        r"(?<![A-Z0-9])(?P<value>AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        0.995,
        Severity.CRITICAL,
    ),
    RegexPattern(
        "ACCESS_TOKEN",
        r"(?:authorization\s*[:=]\s*bearer|bearer)\s+(?P<value>[A-Z0-9._~+/-]{12,})",
        0.98,
        Severity.CRITICAL,
    ),
    RegexPattern(
        "API_KEY",
        r"(?:api[_ -]?key|apikey|client[_ -]?secret)\s*[:=]\s*['\"]?(?P<value>[A-Z0-9_./+~-]{12,})",
        0.97,
        Severity.CRITICAL,
    ),
    RegexPattern(
        "DATABASE_PASSWORD",
        r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?)://[^\s:/@]+:(?P<value>[^\s/@]{3,})@",
        0.99,
        Severity.CRITICAL,
    ),
    RegexPattern(
        "PASSWD",
        r"(?:password|passwd|pwd|密码)\s*[:=]\s*['\"]?(?P<value>[^\s'\",;]{4,128})",
        0.98,
        Severity.CRITICAL,
    ),
)


class SecretDetector(RegexDetector):
    """Detect credentials without requiring a model dependency."""

    name = "secret"

    def __init__(self, patterns: Iterable[RegexPattern] | None = None) -> None:
        super().__init__(DEFAULT_SECRET_PATTERNS if patterns is None else patterns)


__all__ = ["DEFAULT_SECRET_PATTERNS", "SecretDetector"]
