"""The token vault: the part of the system that makes a transform reversible.

Masking and hashing are one-way. Tokenisation is not: the vault holds the
mapping, so a value can go out as ``[[PHONE_3f9a1c04]]``, survive a round trip
through an external model, and come back as itself. That is the whole
hide-and-seek pipeline — hide on the way out, seek on the way in.

Whether a given value is *restorable* is a policy decision, not a vault
decision. A rule that tokenises without ``restore_on_response`` gets a stable
pseudonym whose mapping is never written down, so the same value reads
consistently across a document without anyone being able to walk it back.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass

from ..audit import AuditBus, Channel


TOKEN_PATTERN = re.compile(r"\[\[([A-Z][A-Z0-9_]*)_([0-9a-f]{8,32})\]\]")


@dataclass(frozen=True)
class Restoration:
    """The result of a seek pass over a response."""

    text: str
    restored: int = 0
    unknown_tokens: tuple[str, ...] = ()

    def describe(self) -> str:
        unknown = f", {len(self.unknown_tokens)} unknown" if self.unknown_tokens else ""
        return f"restored {self.restored} token(s){unknown}"


class TokenVault:
    """Stable, opaque placeholders with an optional way back.

    Tokens are derived from a per-vault secret salt, so the same value always
    gets the same token inside one session — repeated mentions stay consistent,
    which matters for the downstream task — while the token itself leaks nothing
    about the value even to someone who can guess it.
    """

    def __init__(self, *, salt: bytes | None = None, digest_size: int = 8, audit: AuditBus | None = None) -> None:
        if not 8 <= digest_size <= 32:
            raise ValueError(f"digest_size must be within [8, 32], got {digest_size}")
        self._salt = salt if salt is not None else secrets.token_bytes(16)
        self._digest_size = digest_size
        self._values: dict[str, str] = {}
        self._audit = audit

    def __len__(self) -> int:
        return len(self._values)

    @property
    def tokens(self) -> tuple[str, ...]:
        return tuple(self._values)

    def token_for(self, value: str, label: str) -> str:
        """Return the token ``value`` would get, without recording anything."""

        digest = hashlib.blake2b(value.encode("utf-8"), key=self._salt, digest_size=16).hexdigest()
        return f"[[{label}_{digest[: self._digest_size]}]]"

    def tokenize(self, value: str, label: str, *, restorable: bool = True) -> str:
        """Replace ``value`` with a token, recording the way back if allowed."""

        token = self.token_for(value, label)
        if restorable:
            self._values[token] = value
        if self._audit is not None:
            # The vault is the one place in the system that keeps a way back
            # from a placeholder to a value, so it is worth an audit record even
            # when nothing goes wrong: a restorable mapping is a stored secret
            # with a lifetime, and the trail is where its lifetime is visible.
            self._audit.record(
                Channel.C4_VAULT_MAPPING,
                component="TokenVault",
                ref=token,
                labels=(label,),
                values=(value,) if restorable else (),
                carries_raw=restorable,
                note="restorable mapping written" if restorable else "pseudonym only, no way back",
            )
        return token

    def restore(self, token: str) -> str | None:
        """Return the original value behind ``token``, or ``None``."""

        return self._values.get(token)

    def restore_text(self, text: str) -> Restoration:
        """Put every restorable value back into ``text``.

        Tokens the vault does not know are left in place and reported rather
        than dropped: a placeholder that survives to the user is a visible bug,
        while a silently deleted one is not.
        """

        restored = 0
        unknown: list[str] = []

        def substitute(match: re.Match[str]) -> str:
            nonlocal restored
            token = match.group(0)
            value = self._values.get(token)
            if value is None:
                unknown.append(token)
                return token
            restored += 1
            return value

        return Restoration(text=TOKEN_PATTERN.sub(substitute, text), restored=restored, unknown_tokens=tuple(unknown))

    def clear(self) -> None:
        """Forget every mapping. Call this when a session ends."""

        if self._audit is not None and self._values:
            self._audit.record(
                Channel.C4_VAULT_MAPPING,
                component="TokenVault",
                note=f"cleared {len(self._values)} mapping(s)",
            )
        self._values.clear()

    def __repr__(self) -> str:
        return f"<TokenVault entries={len(self._values)}>"


__all__ = ["TOKEN_PATTERN", "Restoration", "TokenVault"]
