"""Label-aware, deterministic masking helpers."""

from __future__ import annotations


IDENTITY_LABELS = {
    "DRIVERID",
    "HEALTHCARD",
    "IDCARD",
    "INSURANCEID",
    "MILITARYID",
    "OUTPATIENTID",
    "PASSPORTID",
    "PATIENTID",
    "RESIDENCEID",
    "SOCIALID",
    "TAXID",
    "VISAAUTH",
}
FINANCIAL_LABELS = {"BANKACCOUNT", "FINACCOUNT"}
PHONE_LABELS = {"FAX", "MOBILE", "TEL"}
DEVICE_LABELS = {"IMEI", "IMSI", "MEID", "VIN"}


def _mask_middle(value: str, visible_prefix: int, visible_suffix: int, mask_char: str) -> str:
    if not value:
        return mask_char
    if len(value) <= visible_prefix + visible_suffix:
        return mask_char * len(value)
    masked_length = len(value) - visible_prefix - visible_suffix
    suffix = value[-visible_suffix:] if visible_suffix else ""
    return f"{value[:visible_prefix]}{mask_char * masked_length}{suffix}"


def mask_value(value: str, label: str, *, mask_char: str = "*") -> str:
    """Mask a value while retaining only a label-appropriate minimum preview.

    The function deliberately does not try to preserve every formatting detail:
    predictable output is preferable to accidentally exposing a full identifier.
    """

    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if len(mask_char) != 1:
        raise ValueError("mask_char must contain exactly one character")

    normalized_label = label.upper()
    if normalized_label == "PASSWD":
        return mask_char * max(len(value), 8)
    if normalized_label in IDENTITY_LABELS:
        return _mask_middle(value, 6, 4, mask_char)
    if normalized_label in FINANCIAL_LABELS:
        return _mask_middle(value, 4, 4, mask_char)
    if normalized_label in PHONE_LABELS:
        return _mask_middle(value, 3, 4, mask_char)
    if normalized_label in DEVICE_LABELS:
        return _mask_middle(value, 4, 4, mask_char)
    if normalized_label == "EMAIL" and "@" in value:
        local_part, domain = value.rsplit("@", 1)
        masked_local = _mask_middle(local_part, 1, 0, mask_char)
        return f"{masked_local}@{domain}"
    if normalized_label == "IPV4":
        octets = value.split(".")
        if len(octets) == 4:
            return f"{octets[0]}.*.*.*"
    if normalized_label == "IPV6":
        first_group = value.split(":", 1)[0]
        return f"{first_group}:****::"
    if normalized_label == "MAC":
        parts = value.replace("-", ":").split(":")
        if len(parts) == 6:
            return f"{parts[0]}:{parts[1]}:**:**:**:**"
    if normalized_label in {"ADDRESS", "NAME"}:
        return _mask_middle(value, 1, 0, mask_char)
    if len(value) <= 2:
        return mask_char * max(len(value), 1)
    if len(value) <= 6:
        return _mask_middle(value, 1, 1, mask_char)
    return _mask_middle(value, 2, 2, mask_char)
