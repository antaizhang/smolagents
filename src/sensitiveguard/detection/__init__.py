"""Detection: the fact layer.

Everything here answers *what is in this content*. Nothing here decides what to
do about it — that separation is what the policy layer depends on.
"""

from .base import DetectionReport, Detector, EscalationDetector
from .capability import OCR_CONFIDENCE_FACTOR, CapabilityRouter, ConfidenceScaledDetector, build_chain
from .cascade import DEFAULT_SETTLE_CONFIDENCE, CascadeDetector, CascadeTier
from .llm_tier import PhoneAgentDetector, normalize_number_text
from .patterns import (
    API_KEY,
    BANK_CARD,
    EMAIL,
    ID_CARD,
    KNOWN_LABELS,
    PHONE,
    AmbiguousNumberDetector,
    RegexDetector,
    api_key_detectors,
    bank_card_detector,
    email_detector,
    high_precision_detectors,
    id_card_detector,
    phone_detector,
)


__all__ = [
    "API_KEY",
    "BANK_CARD",
    "DEFAULT_SETTLE_CONFIDENCE",
    "EMAIL",
    "ID_CARD",
    "KNOWN_LABELS",
    "OCR_CONFIDENCE_FACTOR",
    "PHONE",
    "AmbiguousNumberDetector",
    "CapabilityRouter",
    "CascadeDetector",
    "CascadeTier",
    "ConfidenceScaledDetector",
    "DetectionReport",
    "Detector",
    "EscalationDetector",
    "PhoneAgentDetector",
    "RegexDetector",
    "api_key_detectors",
    "bank_card_detector",
    "build_chain",
    "email_detector",
    "high_precision_detectors",
    "id_card_detector",
    "normalize_number_text",
    "phone_detector",
]
