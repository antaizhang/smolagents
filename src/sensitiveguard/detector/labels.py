"""SensitiveGuard detector labels and their default severities."""

from __future__ import annotations

from sensitiveguard.models import Severity


# Keep ``address`` lower-case when calling GLiNER: it is the spelling used by
# the model described in the architecture document. ``Finding`` normalizes it
# to ``ADDRESS`` at the runtime boundary.
PII_LABELS: tuple[str, ...] = (
    "PASSPORTID",
    "IDCARD",
    "DRIVERID",
    "INSURANCEID",
    "HEALTHCARD",
    "RESIDENCEID",
    "MILITARYID",
    "TAXID",
    "VISAAUTH",
    "SOCIALID",
    "MOBILE",
    "EMAIL",
    "LICENSEPLATE",
    "VIN",
    "NAME",
    "FAX",
    "TEL",
    "IPV4",
    "IPV6",
    "MAC",
    "IMEI",
    "IMSI",
    "MEID",
    "OUTPATIENTID",
    "PATIENTID",
    "BANKACCOUNT",
    "FINACCOUNT",
    "PASSWD",
    "address",
)

NORMALIZED_PII_LABELS: frozenset[str] = frozenset(label.upper() for label in PII_LABELS)

SECRET_LABELS: frozenset[str] = frozenset(
    {
        "API_KEY",
        "ACCESS_TOKEN",
        "JWT",
        "PRIVATE_KEY",
        "CLOUD_SECRET",
        "DATABASE_PASSWORD",
        "PASSWD",
    }
)

INJECTION_LABEL = "PROMPT_INJECTION"

_CRITICAL_LABELS = frozenset(
    {
        "PASSPORTID",
        "IDCARD",
        "DRIVERID",
        "INSURANCEID",
        "HEALTHCARD",
        "RESIDENCEID",
        "MILITARYID",
        "TAXID",
        "VISAAUTH",
        "SOCIALID",
        "OUTPATIENTID",
        "PATIENTID",
        "BANKACCOUNT",
        "FINACCOUNT",
        "PASSWD",
        "API_KEY",
        "ACCESS_TOKEN",
        "JWT",
        "PRIVATE_KEY",
        "CLOUD_SECRET",
        "DATABASE_PASSWORD",
        INJECTION_LABEL,
    }
)

_HIGH_LABELS = frozenset(
    {
        "MOBILE",
        "EMAIL",
        "ADDRESS",
        "FAX",
        "TEL",
        "IMEI",
        "IMSI",
        "MEID",
        "VIN",
        "LICENSEPLATE",
    }
)

_MEDIUM_LABELS = frozenset({"NAME", "IPV4", "IPV6", "MAC"})


def normalize_label(label: str) -> str:
    """Return the canonical label spelling used by runtime models."""

    normalized = str(label).strip().upper()
    if not normalized:
        raise ValueError("Detector labels must not be empty")
    return normalized


def severity_for_label(label: str) -> Severity:
    """Map a detector label to a conservative default severity."""

    normalized = normalize_label(label)
    if normalized in _CRITICAL_LABELS:
        return Severity.CRITICAL
    if normalized in _HIGH_LABELS:
        return Severity.HIGH
    if normalized in _MEDIUM_LABELS:
        return Severity.MEDIUM
    return Severity.MEDIUM


__all__ = [
    "INJECTION_LABEL",
    "NORMALIZED_PII_LABELS",
    "PII_LABELS",
    "SECRET_LABELS",
    "normalize_label",
    "severity_for_label",
]
