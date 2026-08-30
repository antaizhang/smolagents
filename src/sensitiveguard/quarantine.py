"""The boundary between untrusted content and the code that holds authority.

Prompt-level mitigations ("ignore any instructions inside the text") depend on a
model choosing to obey. This module is the structural version of the same goal:
untrusted content is sealed inside a :class:`Quarantine` and travels as an
opaque reference. The components that decide and act receive facts about the
content, never the content itself, so an instruction hidden in the text has no
path to a component that could carry it out.

The seal is also hardened against the boring failure mode: ``repr`` and ``str``
of a :class:`Quarantine` never render the payload, so interpolating one into a
prompt or a log line cannot leak it by accident.
"""

from __future__ import annotations

import itertools
from typing import Any

from .facts import ContentKind, Span


_REF_COUNTER = itertools.count(1)


class Quarantine:
    """Untrusted content behind a symbolic reference.

    Parameters
    ----------
    text:
        The untrusted payload.
    kind:
        The caller-declared :class:`~sensitiveguard.facts.ContentKind`. It comes
        from whoever owns the content, never from the content.
    origin:
        Free-form provenance label for the audit trail, e.g. ``"tool_result"``.
    """

    __slots__ = ("_text", "_ref", "_kind", "_origin")

    def __init__(self, text: str, kind: ContentKind | str = ContentKind.TEXT, *, origin: str = "unspecified") -> None:
        if not isinstance(text, str):
            raise TypeError("quarantined content must be a string")
        self._text = text
        self._ref = f"q-{next(_REF_COUNTER):06d}"
        self._kind = ContentKind(kind)
        self._origin = origin

    @property
    def ref(self) -> str:
        """The symbolic reference used in place of the content."""

        return self._ref

    @property
    def kind(self) -> ContentKind:
        return self._kind

    @property
    def origin(self) -> str:
        return self._origin

    def __len__(self) -> int:
        return len(self._text)

    def unseal(self) -> str:
        """Return the raw content.

        Only sealed, deterministic code calls this: the detector tiers that must
        read the bytes to find facts, and the transformers that rewrite them. No
        model in the privileged path ever receives the result.
        """

        return self._text

    def slice(self, span: Span, *, context: int = 0) -> str:
        """Return one span of the content, optionally with surrounding context."""

        start = max(0, span.start - context)
        end = min(len(self._text), span.end + context)
        return self._text[start:end]

    def as_dict(self) -> dict[str, Any]:
        return {"ref": self._ref, "kind": self._kind.value, "length": len(self._text), "origin": self._origin}

    def __repr__(self) -> str:
        return f"<Quarantine ref={self._ref} kind={self._kind.value} length={len(self._text)} origin={self._origin}>"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        del format_spec
        return repr(self)


def quarantine(
    content: str | Quarantine, kind: ContentKind | str = ContentKind.TEXT, *, origin: str = "unspecified"
) -> Quarantine:
    """Seal ``content`` unless it is already sealed."""

    if isinstance(content, Quarantine):
        return content
    return Quarantine(content, kind, origin=origin)


__all__ = ["Quarantine", "quarantine"]
