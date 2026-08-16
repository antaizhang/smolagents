"""Detector protocol shared by all SensitiveGuard detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sensitiveguard.models import DetectionResult


class DetectorUnavailableError(RuntimeError):
    """Raised when an optional detector cannot be used safely."""


class Detector(ABC):
    """Abstract sensitive-content detector.

    Detectors are deliberately synchronous and side-effect free. Optional
    model-backed implementations may load their model lazily on first use.
    """

    name = "detector"

    @abstractmethod
    def detect(self, content: str, context: Any = None) -> DetectionResult:
        """Detect normalized sensitive spans in ``content``."""

    @staticmethod
    def validate_content(content: str) -> None:
        if not isinstance(content, str):
            raise TypeError("Detector content must be a string")


__all__ = ["Detector", "DetectorUnavailableError"]
