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
    # Chinese injections reorder freely ("忽略以上所有隐私规则"), so the strict
    # word-order patterns above miss them.  These variants allow bounded filler
    # between the verb, the target and the noun.
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>忽略[^\n]{0,12}?(?:之前|以上|先前|上面|前面|原有|系统)[^\n]{0,12}?(?:指令|规则|要求|提示|设定|限制))",
        0.99,
        Severity.CRITICAL,
        flags=0,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:无视|不要理会|不用理会|不必遵守|不再遵守|跳过|绕过)[^\n]{0,12}?(?:之前|以上|先前|系统|安全|隐私|原有)[^\n]{0,12}?(?:指令|规则|要求|限制|策略))",
        0.99,
        Severity.CRITICAL,
        flags=0,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:客户|个人|隐私|敏感|用户|全部|所有)[^\n]{0,30}?(?:发送|上传|泄露|外传|发给|传到|同步)[^\n]{0,60}?https?://)",
        0.99,
        Severity.CRITICAL,
        flags=re.IGNORECASE,
    ),
    RegexPattern(
        INJECTION_LABEL,
        r"(?P<value>(?:显示|输出|打印|告诉我|说出)[^\n]{0,8}?(?:系统|开发者|隐藏)[^\n]{0,6}?(?:提示词|提示语|提示|指令))",
        0.98,
        Severity.CRITICAL,
        flags=0,
    ),
)


class InjectionDetector(RegexDetector):
    """Detect common prompt-injection and exfiltration instructions."""

    name = "injection"

    def __init__(self, patterns: Iterable[RegexPattern] | None = None) -> None:
        super().__init__(DEFAULT_INJECTION_PATTERNS if patterns is None else patterns)


__all__ = ["DEFAULT_INJECTION_PATTERNS", "InjectionDetector"]
