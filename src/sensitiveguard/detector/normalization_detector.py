"""Detect PII hidden behind Unicode compatibility and zero-width characters."""

from __future__ import annotations

import unicodedata
from typing import Any

from sensitiveguard.models import DetectionResult, Finding

from .base import Detector


_ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})


class NormalizationDetector(Detector):
    name = "unicode_normalization"

    def __init__(self, detector: Detector) -> None:
        if not isinstance(detector, Detector):
            raise TypeError("NormalizationDetector expects a Detector")
        self.detector = detector

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        self.validate_content(content)
        normalized: list[str] = []
        source_indexes: list[int] = []
        for index, character in enumerate(content):
            if character in _ZERO_WIDTH:
                continue
            for normalized_character in unicodedata.normalize("NFKC", character):
                normalized.append(normalized_character)
                source_indexes.append(index)
        normalized_text = "".join(normalized)
        if normalized_text == content or not normalized_text:
            return DetectionResult()
        result = self.detector.detect(normalized_text, context=context)
        findings: list[Finding] = []
        for finding in result.findings:
            if finding.start < 0 or finding.end > len(source_indexes) or finding.end <= finding.start:
                raise ValueError("Normalized detector returned an invalid span")
            start = source_indexes[finding.start]
            end = source_indexes[finding.end - 1] + 1
            findings.append(
                Finding(
                    label=finding.label,
                    start=start,
                    end=end,
                    score=min(finding.score, 0.98),
                    severity=finding.severity,
                    detector=f"normalized:{finding.detector}",
                    value=content[start:end],
                )
            )
        return DetectionResult(tuple(findings))


__all__ = ["NormalizationDetector"]
