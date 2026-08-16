"""SensitiveGuard transformation primitives."""

from .engine import (
    AppliedTransformation,
    InvalidSpanError,
    TransformationBlockedError,
    TransformationEngine,
    TransformationError,
    TransformationResult,
)
from .generalize import generalize_value
from .mask import mask_value
from .pseudonymize import Pseudonymizer
from .redact import redact_value
from .tokenize import TokenResolutionDisabled, TokenVault


__all__ = [
    "AppliedTransformation",
    "InvalidSpanError",
    "Pseudonymizer",
    "TokenResolutionDisabled",
    "TokenVault",
    "TransformationBlockedError",
    "TransformationEngine",
    "TransformationError",
    "TransformationResult",
    "generalize_value",
    "mask_value",
    "redact_value",
]
