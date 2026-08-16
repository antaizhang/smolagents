"""Comparison primitives shared by the trusted decision layers."""

from __future__ import annotations

import hmac


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two text values in constant time.

    ``hmac.compare_digest`` rejects ``str`` arguments that contain non-ASCII
    characters with a ``TypeError``.  Run identifiers, capability names, policy
    versions and command grammars are ordinary text and may legitimately hold
    non-ASCII characters, so comparing their UTF-8 encodings keeps the timing
    guarantee while always producing a decision instead of an exception.
    """

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


__all__ = ["constant_time_equals"]
