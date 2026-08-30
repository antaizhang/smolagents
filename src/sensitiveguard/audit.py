"""The internal channels, and a bus that can watch them without becoming one.

Most privacy evaluation looks at the last hop: what did the system finally emit.
That misses the interesting half. A guard is a pipeline, and a value can cross a
boundary inside it long before anything is emitted — a detector handing facts to
the policy, the policy handing a verdict to a transformer, a vault writing down
the way back from a token, one agent handing its working notes to the next. Each
of those is a channel, and each one is somewhere a secret can end up where it was
not supposed to be.

This module names those channels and records the crossings. The recording is the
delicate part: an audit log that stores the values it is auditing is a sixth
channel, and the worst one, because it is durable and usually less guarded than
the pipeline. So an :class:`AuditEvent` stores no content. It stores a keyed
digest of each value that crossed, which is enough to answer *did this specific
secret cross this channel* — the question a leak probe asks — and not enough to
answer *what crossed*, which is the question an attacker asks.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Channel(str, Enum):
    """A boundary inside the guard that content or facts can cross.

    The numbering follows the usual way of talking about agent-internal leak
    paths: C1 is the way in, C6 is the way out, and everything between is the
    part a black-box evaluation never sees.
    """

    #: Untrusted content arriving and being sealed.
    C1_INGRESS = "C1_ingress"
    #: The quarantined detector handing facts to the privileged side.
    C2_DETECTOR_TO_POLICY = "C2_detector_to_policy"
    #: Verdicts reaching the code that rewrites the bytes.
    C3_POLICY_TO_TRANSFORM = "C3_policy_to_transform"
    #: A token being written into the vault together with its way back.
    C4_VAULT_MAPPING = "C4_vault_mapping"
    #: One agent handing state to another, including through shared memory.
    C5_AGENT_TO_AGENT = "C5_agent_to_agent"
    #: Content leaving the process for a destination outside it.
    C6_EGRESS = "C6_egress"

    def __str__(self) -> str:
        return self.value


#: Channels that are supposed to carry facts only — a span, a label, a number —
#: and never a value. A raw value seen on one of these is a finding on its own,
#: before anyone asks where it ended up.
FACT_ONLY_CHANNELS = frozenset({Channel.C2_DETECTOR_TO_POLICY, Channel.C3_POLICY_TO_TRANSFORM})


@dataclass(frozen=True)
class AuditEvent:
    """One crossing, recorded by digest.

    ``digests`` are keyed hashes of whatever values the crossing carried, so
    :meth:`AuditBus.channels_carrying` can answer "did *this* value cross here"
    without the record itself holding the value.
    """

    channel: Channel
    component: str
    ref: str
    labels: tuple[str, ...] = ()
    digests: frozenset[str] = frozenset()
    payload_bytes: int = 0
    carries_raw: bool = False
    note: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        shape = f"{self.payload_bytes}B" if self.payload_bytes else "no payload"
        raw = " RAW" if self.carries_raw else ""
        labels = f" labels={','.join(self.labels)}" if self.labels else ""
        note = f" {self.note}" if self.note else ""
        return f"{self.channel.value} {self.component} ref={self.ref} {shape}{raw}{labels}{note}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel.value,
            "component": self.component,
            "ref": self.ref,
            "labels": list(self.labels),
            "digests": sorted(self.digests),
            "payload_bytes": self.payload_bytes,
            "carries_raw": self.carries_raw,
            "note": self.note,
            "detail": dict(self.detail),
        }


class AuditBus:
    """Collects crossings, and answers questions about them by digest.

    One bus per run. The salt is per-bus and never leaves it, so digests are
    comparable inside a run — which is all a leak probe needs — and meaningless
    outside it, which is what stops the audit trail from turning into a rainbow
    table of everyone's phone numbers.
    """

    __slots__ = ("_events", "_salt", "_min_digest_length")

    def __init__(self, *, salt: bytes | None = None, min_digest_length: int = 4) -> None:
        if min_digest_length < 1:
            raise ValueError(f"min_digest_length must be >= 1, got {min_digest_length}")
        self._events: list[AuditEvent] = []
        self._salt = salt if salt is not None else secrets.token_bytes(16)
        self._min_digest_length = min_digest_length

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(self._events)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def digest(self, value: str) -> str:
        """The keyed digest this bus uses for ``value``."""

        return hashlib.blake2b(value.encode("utf-8"), key=self._salt, digest_size=16).hexdigest()

    def digests_of(self, values: Iterable[str]) -> frozenset[str]:
        """Digest every value long enough to be worth tracking.

        Very short strings are skipped: a two-character value collides with half
        the corpus and would make every channel look like it leaked.
        """

        return frozenset(
            self.digest(value) for value in values if isinstance(value, str) and len(value) >= self._min_digest_length
        )

    def record(
        self,
        channel: Channel,
        component: str,
        *,
        ref: str = "-",
        labels: Sequence[str] = (),
        values: Iterable[str] = (),
        payload_bytes: int = 0,
        carries_raw: bool = False,
        note: str = "",
        **detail: Any,
    ) -> AuditEvent:
        """Record one crossing. ``values`` are digested, never stored."""

        event = AuditEvent(
            channel=Channel(channel),
            component=component,
            ref=ref,
            labels=tuple(labels),
            digests=self.digests_of(values),
            payload_bytes=payload_bytes,
            carries_raw=carries_raw,
            note=note,
            detail=dict(detail),
        )
        self._events.append(event)
        return event

    def events_on(self, channel: Channel) -> tuple[AuditEvent, ...]:
        resolved = Channel(channel)
        return tuple(event for event in self._events if event.channel is resolved)

    def channels_carrying(self, value: str) -> tuple[Channel, ...]:
        """Which channels ``value`` crossed, in the order they were first seen.

        This is the leak probe: hold out a secret, run the pipeline, ask where it
        went. A channel that appears here and should not have is a finding no
        output-only evaluation could have produced.
        """

        wanted = self.digest(value)
        seen: list[Channel] = []
        for event in self._events:
            if wanted in event.digests and event.channel not in seen:
                seen.append(event.channel)
        return tuple(seen)

    def crossed(self, value: str, channel: Channel) -> bool:
        return Channel(channel) in self.channels_carrying(value)

    def fact_only_violations(self) -> tuple[AuditEvent, ...]:
        """Crossings that carried a raw value on a facts-only channel."""

        return tuple(event for event in self._events if event.carries_raw and event.channel in FACT_ONLY_CHANNELS)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {channel.value: 0 for channel in Channel}
        for event in self._events:
            counts[event.channel.value] += 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {"summary": self.summary(), "events": [event.as_dict() for event in self._events]}

    def describe(self) -> str:
        lines = [f"audit {len(self._events)} crossing(s)"]
        lines.extend(f"  {event.describe()}" for event in self._events)
        return "\n".join(lines)

    def clear(self) -> None:
        self._events.clear()

    def __repr__(self) -> str:
        return f"<AuditBus events={len(self._events)}>"


__all__ = ["FACT_ONLY_CHANNELS", "AuditBus", "AuditEvent", "Channel"]
