"""Minimal phone-number detection tool.

This module deliberately has one public business function: :func:`detect`.
It performs local deterministic matching and never returns the raw numbers.
"""

from __future__ import annotations

import re


_MAINLAND_MOBILE_PATTERN = re.compile(
    r"(?<!\d)(?:(?:\+?86|0086)[ -]?)?1[3-9]\d(?:[ -]?\d){8}(?!\d)"
)


def detect(text: str) -> dict[str, bool | int]:
    """Determine whether text contains a mainland China mobile number.

    Args:
        text: Complete user input to inspect locally.

    Returns:
        An object containing ``has_phone`` and ``count``. Raw phone numbers are
        never returned.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    count = sum(1 for _ in _MAINLAND_MOBILE_PATTERN.finditer(text))
    return {"has_phone": count > 0, "count": count}


__all__ = ["detect"]
