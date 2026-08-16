"""Deterministic indicators for indirect prompt-injection content."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sensitiveguard.detector.labels import INJECTION_LABEL
from sensitiveguard.detector.regex_detector import RegexDetector, RegexPattern
from sensitiveguard.models import Severity


DEFAULT_INJECTION_PATTERNS: tuple[RegexPattern, ...] = (
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:(?:privacy|security)\s+)?(?:instructions?|rules?|messages?))",
        0.99,
        Severity.CRITICAL,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>disregard\s+(?:all\s+)?(?:previous|prior|system|developer)\s+(?:(?:privacy|security)\s+)?(?:instructions?|rules?|messages?))",
        0.99,
        Severity.CRITICAL,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:reveal|print|return|leak)\s+(?:the\s+)?(?:system|developer|hidden)\s+(?:prompt|instructions?|message))",
        0.98,
        Severity.CRITICAL,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>system\s+instruction\s*:)",
        0.94,
        Severity.HIGH,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:send|upload|post|exfiltrate)\s+(?:all\s+)?(?:private|personal|sensitive|customer|secret)[^\n]{0,100}https?://)",
        0.99,
        Severity.CRITICAL,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>忽略(?:所有|全部)?(?:之前|以上|先前)的?(?:隐私|安全)?(?:指令|规则|要求))",
        0.99,
        Severity.CRITICAL,
        flags=0,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:发送|上传|泄露|外传)(?:所有|全部)?(?:客户|个人|隐私|敏感)[^\n]{0,100}https?://)",
        0.99,
        Severity.CRITICAL,
        flags=re.IGNORECASE,
    ),
)


class InjectionDetector(RegexDetector):
    """Detect common prompt-injection and exfiltration instructions."""

    name = "injection"

    def __init__(self, patterns: Iterable[RegexPattern] | None = None) -> None:
        super().__init__(DEFAULT_INJECTION_PATTERNS if patterns is None else patterns)


__all__ = ["DEFAULT_INJECTION_PATTERNS", "InjectionDetector"]
