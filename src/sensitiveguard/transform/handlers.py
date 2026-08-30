"""Handlers: the code that actually carries out a verdict on one span.

Each handler implements exactly one action and knows nothing about why it was
chosen. That is the point of splitting the decision out — the masker cannot
decide to allow something, and the policy cannot decide how a mask is spelled.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from abc import ABC, abstractmethod

from ..policy.model import Action, Decision
from .vault import TokenVault


MASK_CHARACTER = "*"

#: How many leading and trailing characters survive a mask, per label. Keeping a
#: little shape makes masked output readable enough to debug against without
#: making it identifiable.
MASK_STYLES: dict[str, tuple[int, int]] = {
    "PHONE": (3, 4),
    "BANK_CARD": (0, 4),
    "ID_CARD": (0, 0),
    "API_KEY": (0, 0),
}
DEFAULT_MASK_STYLE = (0, 0)


def normalize_for_hash(value: str, label: str) -> str:
    """Fold a value so equal things hash equally.

    ``138 0013 8000`` and ``+86-13800138000`` are the same subscriber, and a log
    that cannot join them is not much of a log. Normalising before hashing is
    what keeps the key stable across formats.
    """

    folded = unicodedata.normalize("NFKC", value).strip()
    if label == "EMAIL":
        return folded.lower()
    digits = "".join(character for character in folded if character.isdigit())
    if not digits:
        return folded.lower()
    if label == "PHONE":
        # A country code is presentation, not identity: +86 13800138000 and
        # 13800138000 are one subscriber and have to land on one key.
        trimmed = digits.lstrip("0")
        if len(trimmed) == 13 and trimmed.startswith("86"):
            trimmed = trimmed[2:]
        return trimmed or digits
    return digits


class Handler(ABC):
    """Carries out one action against one span's value."""

    action: Action

    @abstractmethod
    def apply(self, value: str, decision: Decision) -> str:
        """Return what should stand in place of ``value``."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} action={self.action.value}>"


class MaskHandler(Handler):
    """One-way. The characters are gone and nothing can bring them back."""

    action = Action.MASK

    def __init__(self, *, styles: dict[str, tuple[int, int]] | None = None) -> None:
        self.styles = dict(MASK_STYLES if styles is None else styles)

    def apply(self, value: str, decision: Decision) -> str:
        if decision.label == "EMAIL" and "@" in value:
            local, _, domain = value.partition("@")
            keep = local[:1] if local else ""
            return f"{keep}{MASK_CHARACTER * max(len(local) - len(keep), 1)}@{domain}"
        prefix, suffix = self.styles.get(decision.label, DEFAULT_MASK_STYLE)
        if len(value) <= prefix + suffix:
            return MASK_CHARACTER * len(value)
        hidden = len(value) - prefix - suffix
        return f"{value[:prefix]}{MASK_CHARACTER * hidden}{value[len(value) - suffix :] if suffix else ''}"


class HashHandler(Handler):
    """One-way, but joinable: the same value always yields the same key.

    The salt is not decoration. An unsalted hash of an 11-digit phone number is
    reversible by anyone willing to spend an afternoon enumerating the space, so
    a deployment that wants its logs to stay pseudonymous supplies a secret salt
    and keeps it out of the log store.
    """

    action = Action.HASH

    def __init__(self, *, salt: bytes | None = None, digest_size: int = 10, prefix: str = "sha256") -> None:
        if not 4 <= digest_size <= 32:
            raise ValueError(f"digest_size must be within [4, 32], got {digest_size}")
        self.salt = salt if salt is not None else secrets.token_bytes(16)
        self.digest_size = digest_size
        self.prefix = prefix

    def apply(self, value: str, decision: Decision) -> str:
        normalized = normalize_for_hash(value, decision.label)
        digest = hashlib.blake2b(normalized.encode("utf-8"), key=self.salt, digest_size=16).hexdigest()
        return f"<{decision.label}:{self.prefix}:{digest[: self.digest_size]}>"


class TokenizeHandler(Handler):
    """Reversible, when the policy says the response should be restored."""

    action = Action.TOKENIZE

    def __init__(self, vault: TokenVault) -> None:
        self.vault = vault

    def apply(self, value: str, decision: Decision) -> str:
        return self.vault.tokenize(value, decision.label, restorable=decision.restore_on_response)


def default_handlers(vault: TokenVault, *, hash_salt: bytes | None = None) -> dict[Action, Handler]:
    """The handler set for the three transforming actions.

    ``allow`` needs no handler, and ``block``/``review`` are control flow — they
    stop the content being released rather than rewriting it — so they are
    handled by the router, not here.
    """

    return {
        Action.MASK: MaskHandler(),
        Action.HASH: HashHandler(salt=hash_salt),
        Action.TOKENIZE: TokenizeHandler(vault),
    }


__all__ = [
    "DEFAULT_MASK_STYLE",
    "MASK_CHARACTER",
    "MASK_STYLES",
    "Handler",
    "HashHandler",
    "MaskHandler",
    "TokenizeHandler",
    "default_handlers",
    "normalize_for_hash",
]
