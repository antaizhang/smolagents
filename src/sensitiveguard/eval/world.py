"""Materialize a scenario into a disposable world wired to recording sinks."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .scenario import Scenario, Sink
from .sinks import SinkRecorder, record_new_artifacts, snapshot_tree


class ScenarioWorld:
    """Files, database rows, RAG chunks and egress sinks for one scenario run.

    The same world backs every baseline, so a difference in recorded traffic is
    attributable to the runtime rather than to a difference in the environment.
    """

    def __init__(self, scenario: Scenario, *, parent_dir: Path | None = None) -> None:
        self.scenario = scenario
        self.recorder = SinkRecorder()
        # Resolve the temporary base before creating the root: on macOS ``/var``
        # is a symlink and the strict file guard rejects any protected path with
        # a symlink among its parents.
        base = (Path(parent_dir) if parent_dir is not None else Path(tempfile.gettempdir())).resolve()
        base.mkdir(parents=True, exist_ok=True)
        self._temporary_root = Path(
            tempfile.mkdtemp(prefix=f"sg-bench-{scenario.scenario_id[:24]}-", dir=str(base))
        ).resolve()
        self.root = self._temporary_root
        self.acquired_fields: list[str] = []
        self._baseline_fingerprint: dict[str, str] = {}

        for relative, content in scenario.files.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        self._baseline_fingerprint = snapshot_tree(self.root)

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> ScenarioWorld:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        shutil.rmtree(self._temporary_root, ignore_errors=True)

    def finalize_artifacts(self) -> None:
        """Record files the run created or changed before the world is torn down."""

        record_new_artifacts(self.recorder, self.root, self._baseline_fingerprint)

    @property
    def substitutions(self) -> dict[str, str]:
        return {"root": str(self.root)}

    # -- egress sinks ------------------------------------------------------

    def llm_client(self, prompt: Any) -> str:
        self.recorder.record(Sink.EXTERNAL_LLM, "safe_llm_call", prompt, target=self.scenario.recipient)
        return self.scenario.llm_response

    def http_transport(self, url: Any, body: Any) -> dict[str, Any]:
        host = (urlsplit(str(url)).hostname or "unknown").lower()
        self.recorder.record(Sink.HTTP, "safe_http_post", {"url": url, "body": body}, target=host)
        return dict(self.scenario.http_response)

    def message_sender(self, recipient: Any, body: Any) -> dict[str, Any]:
        self.recorder.record(Sink.MESSAGE, "safe_send_message", body, target=str(recipient))
        return {"status": "sent"}

    # -- data sources ------------------------------------------------------

    def database_executor(
        self,
        table: str,
        fields: Sequence[str] | None,
        filters: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        rows = self.scenario.database.get(str(table), ())
        requested = tuple(fields or ())
        wildcard = not requested or "*" in requested
        selected: list[dict[str, Any]] = []
        for row in rows:
            if filters and any(str(row.get(key)) != str(value) for key, value in filters.items()):
                continue
            projected = dict(row) if wildcard else {key: row[key] for key in requested if key in row}
            selected.append(projected)
            for key in projected:
                self.acquired_fields.append(key)
        return selected

    def rag_retriever(
        self,
        query: str,
        top_k: int,
        scopes: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        del query
        allowed = set(scopes or ())
        chunks = [
            dict(chunk) for chunk in self.scenario.rag_chunks if not allowed or str(chunk.get("scope", "")) in allowed
        ]
        selected = chunks[: max(0, int(top_k))]
        for chunk in selected:
            for key in chunk:
                if key != "scope":
                    self.acquired_fields.append(key)
        return selected

    # -- oracle inputs -----------------------------------------------------

    @property
    def necessary_field_names(self) -> frozenset[str]:
        scenario = self.scenario
        declared = scenario.necessary_data_fields or (*scenario.required_fields, *scenario.allowed_scope)
        return frozenset(name.casefold() for name in declared)

    def data_minimization_counts(self) -> tuple[int, int]:
        """Return ``(necessary_fields_acquired, total_fields_acquired)``."""

        necessary_names = self.necessary_field_names
        total = len(self.acquired_fields)
        necessary = sum(1 for field in self.acquired_fields if field.casefold() in necessary_names)
        return necessary, total


__all__ = ["ScenarioWorld"]
