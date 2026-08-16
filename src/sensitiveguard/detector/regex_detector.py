"""Standard-library regex detector for deterministic PII formats."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sensitiveguard.detector.base import Detector
from sensitiveguard.detector.composite import deduplicate_findings
from sensitiveguard.detector.labels import severity_for_label
from sensitiveguard.models import DetectionResult, Finding, Severity


Validator = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class RegexPattern:
    """One regex-backed detector rule.

    ``group`` selects the sensitive value rather than surrounding contextual
    text. A value of ``None`` selects the complete match.
    """

    label: str
    pattern: str
    score: float = 0.95
    severity: Severity | None = None
    flags: int = re.IGNORECASE
    group: str | int | None = "value"
    validator: Validator | None = None

    def __post_init__(self) -> None:
        if not self.label.strip():
            raise ValueError("RegexPattern.label must not be empty")
        if not 0 <= self.score <= 1:
            raise ValueError("RegexPattern.score must be between 0 and 1")
        if self.severity is not None and not isinstance(self.severity, Severity):
            object.__setattr__(self, "severity", Severity(str(self.severity).strip().lower()))
        re.compile(self.pattern, self.flags)


def _is_ip_version(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def _prefixed(prefixes: tuple[str, ...], value_pattern: str) -> str:
    prefix_pattern = "|".join(re.escape(prefix) for prefix in prefixes)
    # Prevent an English prefix from matching the beginning of an unrelated
    # word (for example ``name`` in ``names``). Chinese prefixes are unaffected.
    return rf"(?:{prefix_pattern})(?![A-Z])\s*(?:number|no\.?|号码|号)?\s*[:：=#]?\s*(?P<value>{value_pattern})"


DEFAULT_PII_PATTERNS: tuple[RegexPattern, ...] = (
    RegexPattern("PASSPORTID", _prefixed(("passport", "护照"), r"[A-Z][A-Z0-9]{5,17}"), 0.98),
    RegexPattern(
        "IDCARD",
        r"(?<!\d)(?P<value>[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)",
        0.995,
    ),
    RegexPattern("DRIVERID", _prefixed(("driver id", "driver license", "驾驶证"), r"[A-Z0-9-]{6,24}"), 0.97),
    RegexPattern("INSURANCEID", _prefixed(("insurance id", "insurance number", "保险号"), r"[A-Z0-9-]{6,32}"), 0.96),
    RegexPattern("HEALTHCARD", _prefixed(("health card", "医保卡", "健康卡"), r"[A-Z0-9-]{6,32}"), 0.97),
    RegexPattern("RESIDENCEID", _prefixed(("residence id", "居住证"), r"[A-Z0-9-]{6,32}"), 0.97),
    RegexPattern("MILITARYID", _prefixed(("military id", "军官证", "士兵证"), r"[A-Z0-9-]{5,32}"), 0.97),
    RegexPattern("TAXID", _prefixed(("tax id", "taxpayer id", "纳税人识别号", "税号"), r"[A-Z0-9-]{8,32}"), 0.98),
    RegexPattern("VISAAUTH", _prefixed(("visa authorization", "visa id", "签证号"), r"[A-Z0-9-]{5,32}"), 0.96),
    RegexPattern("SOCIALID", _prefixed(("social id", "social security", "社保号"), r"[A-Z0-9-]{6,32}"), 0.98),
    RegexPattern("MOBILE", r"(?<!\d)(?P<value>(?:\+?86[- ]?)?1[3-9]\d{9})(?!\d)", 0.99),
    RegexPattern("EMAIL", r"(?<![\w.+-])(?P<value>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", 0.99),
    RegexPattern("LICENSEPLATE", r"(?<![A-Z0-9])(?P<value>[\u4e00-\u9fff][A-Z][A-Z0-9]{5,6})(?![A-Z0-9])", 0.94),
    RegexPattern("VIN", r"(?<![A-HJ-NPR-Z0-9])(?P<value>[A-HJ-NPR-Z0-9]{17})(?![A-HJ-NPR-Z0-9])", 0.97),
    RegexPattern(
        "NAME",
        _prefixed(("name", "customer name", "姓名", "客户姓名"), r"[\u4e00-\u9fff]{2,6}|[A-Z][A-Z .'-]{1,80}"),
        0.88,
    ),
    RegexPattern("FAX", _prefixed(("fax", "传真"), r"(?:\+?\d{1,3}[- ]?)?(?:\d[- ]?){6,14}\d"), 0.96),
    RegexPattern(
        "TEL", _prefixed(("tel", "telephone", "phone", "电话"), r"(?:\+?\d{1,3}[- ]?)?(?:\d[- ]?){6,14}\d"), 0.95
    ),
    RegexPattern(
        "IPV4",
        r"(?<![\d.])(?P<value>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?![\d.])",
        0.99,
        validator=lambda value: _is_ip_version(value, 4),
    ),
    RegexPattern(
        "IPV6",
        r"(?<![0-9A-F:])(?P<value>[0-9A-F:]{2,39})(?![0-9A-F:])",
        0.96,
        validator=lambda value: _is_ip_version(value, 6),
    ),
    RegexPattern("MAC", r"(?<![0-9A-F])(?P<value>(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2})(?![0-9A-F])", 0.99),
    RegexPattern("IMEI", _prefixed(("imei",), r"\d{15}"), 0.99),
    RegexPattern("IMSI", _prefixed(("imsi",), r"\d{14,15}"), 0.99),
    RegexPattern("MEID", _prefixed(("meid",), r"[A-F0-9]{14,18}"), 0.99),
    RegexPattern("OUTPATIENTID", _prefixed(("outpatient id", "门诊号"), r"[A-Z0-9-]{4,32}"), 0.97),
    RegexPattern("PATIENTID", _prefixed(("patient id", "病人号", "患者编号"), r"[A-Z0-9-]{4,32}"), 0.97),
    RegexPattern(
        "BANKACCOUNT", _prefixed(("bank account", "bank card", "银行卡", "银行账户"), r"(?:\d[ -]?){11,25}\d"), 0.99
    ),
    RegexPattern(
        "FINACCOUNT", _prefixed(("financial account", "finance account", "资金账号"), r"[A-Z0-9-]{6,32}"), 0.97
    ),
    RegexPattern("PASSWD", _prefixed(("password", "passwd", "pwd", "密码"), r"[^\s,;]{4,128}"), 0.99),
    RegexPattern("address", _prefixed(("address", "地址", "住址"), r"[^\n\r,;]{4,160}"), 0.9),
)


class RegexDetector(Detector):
    """Detect deterministic PII formats using configurable regular expressions."""

    name = "regex"

    def __init__(self, patterns: Iterable[RegexPattern] | None = None) -> None:
        self.patterns = tuple(DEFAULT_PII_PATTERNS if patterns is None else patterns)
        if any(not isinstance(pattern, RegexPattern) for pattern in self.patterns):
            raise TypeError("RegexDetector patterns must be RegexPattern instances")
        self._compiled = tuple((spec, re.compile(spec.pattern, spec.flags)) for spec in self.patterns)

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        del context
        self.validate_content(content)
        findings: list[Finding] = []
        for spec, pattern in self._compiled:
            for match in pattern.finditer(content):
                group = 0 if spec.group is None else spec.group
                try:
                    start, end = match.span(group)
                except (IndexError, KeyError) as error:
                    raise ValueError(f"Regex pattern for {spec.label} has no group {group!r}") from error
                if start < 0 or end <= start:
                    continue
                value = content[start:end]
                if spec.validator is not None and not spec.validator(value):
                    continue
                findings.append(
                    Finding(
                        label=spec.label,
                        start=start,
                        end=end,
                        score=spec.score,
                        severity=spec.severity or severity_for_label(spec.label),
                        detector=self.name,
                        value=value,
                    )
                )
        return DetectionResult(deduplicate_findings(findings))


__all__ = ["DEFAULT_PII_PATTERNS", "RegexDetector", "RegexPattern"]
