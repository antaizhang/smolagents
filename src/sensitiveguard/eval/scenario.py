"""What a benchmark case looks like once it is in this repository's shape.

Six benchmarks, six upstream formats, one internal one. An :class:`Episode` is
the common denominator: a task, some data the agent holds, some untrusted
documents it will read, and an outward action it will take. Everything the six
benchmarks disagree about — whether the interesting part is the injected
instruction, the over-shared field, or the browser action — is expressed by
which of those parts is populated and what the ground truth says about it.

The fields that matter for scoring are deliberately separate:

``required_fields``
    What the task genuinely needs. Withholding these is the utility cost of a
    guard, and a guard that scores well on privacy by emptying every message
    fails here, which is the point of measuring both.
``forbidden_fields``
    What must not reach this destination. Not "sensitive data" in the abstract —
    the same field is required in one scenario and forbidden in the next, which
    is the whole idea of contextual integrity and the reason the destination is
    part of every policy decision.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DATA_ROOT = Path(__file__).with_name("datasets")


@dataclass(frozen=True)
class Directive:
    """An instruction hidden inside untrusted content.

    This is the injection, expressed as data rather than as prose, so a run is
    reproducible and the scorer can say exactly what the attacker wanted. An
    agent that reads untrusted content with the authority to act will carry it
    out; an agent whose planner never sees the content cannot.
    """

    goal: str
    destination: str
    fields: tuple[str, ...] = ()
    text: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Directive:
        return cls(
            goal=str(data.get("goal", "exfiltrate")),
            destination=str(data["destination"]),
            fields=tuple(str(item) for item in data.get("fields", ())),
            text=str(data.get("text", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {"goal": self.goal, "destination": self.destination, "fields": list(self.fields), "text": self.text}


@dataclass(frozen=True)
class Document:
    """One untrusted thing the agent reads through a tool.

    ``origin`` is recorded on the quarantine handle, so the audit trail can tell
    a document the user pasted from a document a web page served.
    """

    tool: str
    content: str
    kind: str = "text"
    origin: str = "tool_result"
    directives: tuple[Directive, ...] = ()

    @property
    def injected(self) -> bool:
        return bool(self.directives)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Document:
        return cls(
            tool=str(data.get("tool", "read")),
            content=str(data.get("content", "")),
            kind=str(data.get("kind", "text")),
            origin=str(data.get("origin", "tool_result")),
            directives=tuple(Directive.from_dict(item) for item in data.get("directives", ())),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "content": self.content,
            "kind": self.kind,
            "origin": self.origin,
            "directives": [directive.as_dict() for directive in self.directives],
        }


@dataclass(frozen=True)
class Action:
    """The outward step: the part that makes this an agent and not a filter.

    ``fields`` is what an unguarded agent actually puts in the message — taken
    from the upstream trajectory, over-sharing included. It is not what the task
    needs; that is ``Episode.required_fields``, and the gap between the two is
    what the privacy benchmarks are about.
    """

    tool: str
    destination: str
    purpose: str = "task_completion"
    fields: tuple[str, ...] = ()
    quotes: tuple[int, ...] = ()
    template: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Action:
        return cls(
            tool=str(data["tool"]),
            destination=str(data["destination"]),
            purpose=str(data.get("purpose", "task_completion")),
            fields=tuple(str(item) for item in data.get("fields", ())),
            quotes=tuple(int(item) for item in data.get("quotes", ())),
            template=str(data.get("template", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "destination": self.destination,
            "purpose": self.purpose,
            "fields": list(self.fields),
            "quotes": list(self.quotes),
            "template": self.template,
        }


@dataclass(frozen=True)
class Episode:
    """One benchmark case, ready to run."""

    id: str
    instruction: str
    action: Action
    profile: Mapping[str, str] = field(default_factory=dict)
    documents: tuple[Document, ...] = ()
    required_fields: frozenset[str] = frozenset()
    forbidden_fields: frozenset[str] = frozenset()
    tags: tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        unknown = sorted((self.required_fields | self.forbidden_fields) - set(self.profile))
        if unknown:
            raise ValueError(f"episode {self.id}: scored field(s) {', '.join(unknown)} are not in the profile")
        contested = sorted(self.required_fields & self.forbidden_fields)
        if contested:
            raise ValueError(
                f"episode {self.id}: field(s) {', '.join(contested)} are both required and forbidden; "
                "a case that cannot be passed is a broken case, not a hard one"
            )

    @property
    def injected(self) -> bool:
        return any(document.injected for document in self.documents)

    @property
    def directives(self) -> tuple[Directive, ...]:
        return tuple(directive for document in self.documents for directive in document.directives)

    def value_of(self, label: str) -> str | None:
        return self.profile.get(label)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Episode:
        profile = {str(key): str(value) for key, value in (data.get("profile") or {}).items()}
        return cls(
            id=str(data["id"]),
            instruction=str(data.get("instruction", "")),
            action=Action.from_dict(data["action"]),
            profile=profile,
            documents=tuple(Document.from_dict(item) for item in data.get("documents", ())),
            required_fields=frozenset(str(item) for item in data.get("required_fields", ())),
            forbidden_fields=frozenset(str(item) for item in data.get("forbidden_fields", ())),
            tags=tuple(str(item) for item in data.get("tags", ())),
            notes=str(data.get("notes", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "instruction": self.instruction,
            "action": self.action.as_dict(),
            "profile": dict(self.profile),
            "documents": [document.as_dict() for document in self.documents],
            "required_fields": sorted(self.required_fields),
            "forbidden_fields": sorted(self.forbidden_fields),
            "tags": list(self.tags),
            "notes": self.notes,
        }


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    """Read a JSONL file, skipping blank lines and ``#`` comments."""

    resolved = Path(path)
    with resolved.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError as error:
                raise ValueError(f"{resolved}:{number}: {error}") from error


def load_episodes(source: str | Path | Iterable[Mapping[str, Any]]) -> tuple[Episode, ...]:
    """Load episodes from a JSONL path or an iterable of mappings."""

    if isinstance(source, (str, Path)):
        records: Iterable[Mapping[str, Any]] = read_jsonl(source)
    else:
        records = source
    return tuple(Episode.from_dict(record) for record in records)


def bundled(name: str) -> Path:
    """Path to a dataset shipped with the package."""

    path = DATA_ROOT / name
    if not path.is_file():
        raise FileNotFoundError(f"no bundled dataset named {name!r} in {DATA_ROOT}")
    return path


def write_jsonl(path: str | Path, records: Sequence[Mapping[str, Any]], *, header: str = "") -> None:
    """Write a dataset, one JSON object per line."""

    resolved = Path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("w", encoding="utf-8") as handle:
        if header:
            for line in header.strip().splitlines():
                handle.write(f"# {line}\n".replace("#  ", "# "))
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


__all__ = [
    "DATA_ROOT",
    "Action",
    "Directive",
    "Document",
    "Episode",
    "bundled",
    "load_episodes",
    "read_jsonl",
    "write_jsonl",
]
