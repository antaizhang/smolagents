"""Conservative generalization helpers."""

from __future__ import annotations

import ipaddress
import re


_CHINESE_ADMINISTRATIVE_AREA = re.compile(r"^(.{1,12}?(?:特别行政区|自治区|省|市))")


def generalize_value(value: str, label: str) -> str:
    """Reduce a value to a coarse representation suitable for analytics.

    Unknown labels use an opaque marker rather than an unsafe heuristic.
    """

    if not isinstance(value, str):
        raise TypeError("value must be a string")

    normalized_label = label.upper()
    if normalized_label == "ADDRESS":
        match = _CHINESE_ADMINISTRATIVE_AREA.match(value.strip())
        return match.group(1) if match else "[GENERALIZED:ADDRESS]"
    if normalized_label == "IPV4":
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            return "[GENERALIZED:IPV4]"
        network = ipaddress.IPv4Network(f"{address}/16", strict=False)
        first, second, _, _ = str(network.network_address).split(".")
        return f"{first}.{second}.x.x/16"
    if normalized_label == "IPV6":
        try:
            address = ipaddress.IPv6Address(value)
        except ipaddress.AddressValueError:
            return "[GENERALIZED:IPV6]"
        network = ipaddress.IPv6Network(f"{address}/48", strict=False)
        return f"{network.network_address.compressed}/48"
    if normalized_label == "EMAIL" and "@" in value:
        return f"[EMAIL_USER]@{value.rsplit('@', 1)[1]}"
    if normalized_label == "NAME":
        return "[PERSON]"
    if normalized_label in {"FAX", "MOBILE", "TEL"}:
        return "[PHONE_REGION]"
    return f"[GENERALIZED:{normalized_label or 'SENSITIVE'}]"
