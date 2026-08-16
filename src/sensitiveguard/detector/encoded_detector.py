"""Detect sensitive text hidden in common single-layer encodings."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from sensitiveguard.models import DetectionResult, Finding, Severity

from .base import Detector


_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SEVERITY = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class EncodedPayloadDetector(Detector):
    """Decode bounded tokens and mark the complete encoded token for removal."""

    name = "encoded_payload"

    def __init__(self, detector: Detector, *, max_decoded_bytes: int = 16_384) -> None:
        if not isinstance(detector, Detector):
            raise TypeError("EncodedPayloadDetector expects a Detector")
        if max_decoded_bytes < 64:
            raise ValueError("max_decoded_bytes is too small")
        self.detector = detector
        self.max_decoded_bytes = max_decoded_bytes

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        self.validate_content(content)
        candidates: list[tuple[int, int, str, Callable[[str], str]]] = []
        candidates.extend(
            (match.start(), match.end(), "url", self._decode_url) for match in _PERCENT.finditer(content)
        )
        candidates.extend(
            (match.start(), match.end(), "base64", self._decode_base64) for match in _BASE64.finditer(content)
        )
        candidates.extend((match.start(), match.end(), "hex", self._decode_hex) for match in _HEX.finditer(content))
        findings: list[Finding] = []
        seen_spans: set[tuple[int, int]] = set()
        for start, end, codec, decoder in sorted(candidates, key=lambda item: (item[0], item[1], item[2])):
            if (start, end) in seen_spans:
                continue
            token = content[start:end]
            try:
                decoded = decoder(token)
            except (UnicodeDecodeError, ValueError, binascii.Error):
                continue
            if not decoded or len(decoded.encode("utf-8")) > self.max_decoded_bytes:
                continue
            result = self.detector.detect(decoded, context=context)
            if not result.findings:
                continue
            winner = max(
                result.findings,
                key=lambda item: (_SEVERITY[item.severity], item.score, item.end - item.start, item.label),
            )
            findings.append(
                Finding(
                    label=winner.label,
                    start=start,
                    end=end,
                    score=min(winner.score, 0.97),
                    severity=winner.severity,
                    detector=f"encoded:{codec}:{winner.detector}",
                    value=token,
                )
            )
            seen_spans.add((start, end))
        return DetectionResult(tuple(findings))

    @staticmethod
    def _decode_url(value: str) -> str:
        return unquote(value, encoding="utf-8", errors="strict")

    @staticmethod
    def _decode_base64(value: str) -> str:
        return base64.b64decode(value, validate=True).decode("utf-8")

    @staticmethod
    def _decode_hex(value: str) -> str:
        return bytes.fromhex(value).decode("utf-8")


__all__ = ["EncodedPayloadDetector"]
