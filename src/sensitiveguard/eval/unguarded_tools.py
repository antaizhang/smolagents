"""Unguarded comparison tools used only by the B0-B2 benchmark baselines.

These deliberately reproduce the *absence* of a privacy runtime: they expose the
same tool names and schemas as the SensitiveGuard tools so a scenario script runs
unchanged across baselines, while applying only the capabilities the baseline
declares. Without them the B0-B2 rows of the acceptance table would have to be
asserted rather than measured.

They are measurement instruments. They are never exported from the package root,
never registered with a real agent, and only ever talk to the recording sinks of
a ``ScenarioWorld``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sensitiveguard.models import Action, DecisionSet, DetectionResult, GuardStage, PolicyDecision
from smolagents.tools import Tool

from .baselines import BaselineConfig
from .capture import BaselineCapture
from .world import ScenarioWorld


UNSUPPORTED = "UNSUPPORTED_IN_BASELINE"


class _UnguardedTool(Tool):
    """Base class holding the baseline capabilities and the scenario world."""

    output_type = "object"

    def __init__(
        self,
        *,
        world: ScenarioWorld,
        baseline: BaselineConfig,
        detector: Any,
        transformer: Any,
        capture: BaselineCapture,
    ) -> None:
        super().__init__()
        self._world = world
        self._baseline = baseline
        self._detector = detector
        self._transformer = transformer
        self._capture = capture

    # -- capability helpers ------------------------------------------------

    def _detect(self, text: str) -> DetectionResult:
        if not self._baseline.detection or self._detector is None:
            return DetectionResult()
        with self._capture.probe.measure():
            detection = self._detector.detect(text)
        self._capture.note_detection(detection)
        return detection

    def _redact_for_egress(self, payload: Any) -> Any:
        """Uniformly redact every detected span, ignoring purpose and destination."""

        if not self._baseline.uniform_redaction:
            return payload
        return self._walk(payload)

    def _walk(self, payload: Any) -> Any:
        if isinstance(payload, str):
            return self._redact_text(payload)
        if isinstance(payload, dict):
            return {key: self._walk(item) for key, item in payload.items()}
        if isinstance(payload, (list, tuple)):
            return [self._walk(item) for item in payload]
        return payload

    def _redact_text(self, text: str) -> str:
        detection = self._detect(text)
        if not detection.findings:
            return text
        decisions = DecisionSet(
            tuple(
                PolicyDecision(
                    finding=finding,
                    action=Action.REDACT,
                    reason="Uniform redaction baseline redacts every detected span",
                    policy_id="B2-UNIFORM-REDACT",
                    severity=finding.severity,
                    allowed_after_transform=True,
                    necessary=False,
                )
                for finding in detection.findings
            )
        )
        with self._capture.probe.measure():
            redacted = self._transformer.apply(text, decisions, run_id=f"baseline-{self._baseline.baseline.value}")
        self._capture.note_decisions(decisions, stage=GuardStage.TOOL_INPUT)
        return redacted

    @staticmethod
    def _unsupported(capability: str) -> dict[str, Any]:
        return {"status": UNSUPPORTED, "reason": f"This baseline does not implement {capability}."}


class UnguardedDetectTool(_UnguardedTool):
    name = "detect_sensitive_data"
    description = "Detect sensitive spans in text."
    inputs = {"text": {"type": "string", "description": "Text to inspect."}}

    def forward(self, text: str) -> dict[str, Any]:
        if not self._baseline.detection:
            return self._unsupported("sensitive-data detection")
        return self._detect(text).to_dict()


class UnguardedEvaluatePolicyTool(_UnguardedTool):
    name = "evaluate_data_policy"
    description = "Evaluate a privacy policy for text."
    inputs = {"text": {"type": "string", "description": "Text to evaluate."}}

    def forward(self, text: str) -> dict[str, Any]:
        del text
        return self._unsupported("context-aware policy evaluation")


class UnguardedSanitizeTextTool(_UnguardedTool):
    name = "sanitize_text"
    description = "Return a safe representation of text."
    inputs = {"text": {"type": "string", "description": "Text to sanitize."}}

    def forward(self, text: str) -> dict[str, Any]:
        if not self._baseline.uniform_redaction:
            return self._unsupported("text sanitization")
        return {"status": "TRANSFORMED", "content": self._redact_text(text)}


class UnguardedScanFileTool(_UnguardedTool):
    name = "scan_file"
    description = "Scan one file for sensitive data."
    inputs = {"path": {"type": "string", "description": "File path."}}

    def forward(self, path: str) -> dict[str, Any]:
        if not self._baseline.detection:
            return self._unsupported("file scanning")
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as error:
            return {"status": "FAILED", "reason": str(error)}
        return {"status": "OK", "counts": self._detect(content).counts()}


class UnguardedScanDirectoryTool(_UnguardedTool):
    name = "scan_directory"
    description = "Scan a directory for sensitive data."
    inputs = {"path": {"type": "string", "description": "Directory path."}}

    def forward(self, path: str) -> dict[str, Any]:
        if not self._baseline.detection:
            return self._unsupported("directory scanning")
        inventory: dict[str, Any] = {}
        for candidate in sorted(Path(path).rglob("*")):
            if not candidate.is_file():
                continue
            try:
                content = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            inventory[candidate.name] = self._detect(content).counts()
        return {"status": "OK", "files": inventory}


class UnguardedReadFileTool(_UnguardedTool):
    name = "safe_read_file"
    description = "Read a file."
    inputs = {"path": {"type": "string", "description": "File path."}}

    def forward(self, path: str) -> dict[str, Any]:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as error:
            return {"status": "FAILED", "reason": str(error)}
        # No memory guard in these baselines: the raw content becomes the
        # observation and therefore enters agent memory verbatim.
        return {"status": "OK", "content": content}


class UnguardedSanitizeFileTool(_UnguardedTool):
    name = "sanitize_file"
    description = "Write a sanitized copy of a file."
    inputs = {
        "input": {"type": "string", "description": "Source file."},
        "output": {"type": "string", "description": "Destination file."},
        "strategy": {"type": "string", "description": "Sanitization strategy.", "nullable": True},
    }

    def forward(self, input: str, output: str, strategy: str | None = None) -> dict[str, Any]:  # noqa: A002
        del strategy
        if not self._baseline.uniform_redaction:
            return self._unsupported("file sanitization")
        source = Path(input)
        destination = Path(output)
        if source == destination:
            return {"status": "FAILED", "reason": "source and destination are identical"}
        try:
            content = source.read_text(encoding="utf-8")
        except OSError as error:
            return {"status": "FAILED", "reason": str(error)}
        destination.write_text(self._redact_text(content), encoding="utf-8")
        return {"status": "OK", "output": str(destination)}


class UnguardedVerifyFileTool(_UnguardedTool):
    name = "verify_sanitized_file"
    description = "Verify that a file no longer contains sensitive data."
    inputs = {"path": {"type": "string", "description": "File to verify."}}

    def forward(self, path: str) -> dict[str, Any]:
        if not self._baseline.detection:
            return self._unsupported("sanitization verification")
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError as error:
            return {"status": "FAILED", "reason": str(error)}
        counts = self._detect(content).counts()
        return {"status": "PASS" if not counts else "FAIL", "counts": counts}


class UnguardedLLMCallTool(_UnguardedTool):
    name = "safe_llm_call"
    description = "Send text to an external LLM."
    inputs = {
        "text": {"type": "string", "description": "Content to analyze."},
        "purpose": {"type": "string", "description": "Declared purpose.", "nullable": True},
    }

    def forward(self, text: str, purpose: str | None = None) -> dict[str, Any]:
        del purpose
        response = self._world.llm_client(self._redact_for_egress(text))
        return {"status": "OK", "content": response}


class UnguardedHTTPPostTool(_UnguardedTool):
    name = "safe_http_post"
    description = "POST a payload to a URL."
    inputs = {
        "url": {"type": "string", "description": "Destination URL."},
        "body": {"type": ["string", "object"], "description": "Payload."},
    }

    def forward(self, url: str, body: Any) -> dict[str, Any]:
        response = self._world.http_transport(url, self._redact_for_egress(body))
        return {"status": "OK", "content": response}


class UnguardedSendMessageTool(_UnguardedTool):
    name = "safe_send_message"
    description = "Send a message to a recipient."
    inputs = {
        "recipient": {"type": "string", "description": "Recipient."},
        "body": {"type": "string", "description": "Message body."},
    }

    def forward(self, recipient: str, body: str) -> dict[str, Any]:
        self._world.message_sender(recipient, self._redact_for_egress(body))
        return {"status": "SENT", "recipient": recipient}


class UnguardedQueryDatabaseTool(_UnguardedTool):
    name = "safe_query_database"
    description = "Query a database table."
    inputs = {
        "table": {"type": "string", "description": "Table name."},
        "fields": {"type": "array", "description": "Requested fields."},
        "filters": {"type": "object", "description": "Equality filters.", "nullable": True},
    }

    def forward(self, table: str, fields: list[str], filters: dict[str, Any] | None = None) -> dict[str, Any]:
        rows = self._world.database_executor(table, fields, filters or {})
        return {"status": "OK", "rows": rows}


class UnguardedRetrieveRAGTool(_UnguardedTool):
    name = "safe_retrieve_rag"
    description = "Retrieve chunks from a RAG index."
    inputs = {
        "query": {"type": "string", "description": "Retrieval query."},
        "top_k": {"type": "integer", "description": "Number of chunks.", "nullable": True},
    }

    def forward(self, query: str, top_k: int | None = None) -> dict[str, Any]:
        # No authorized retrieval scope is applied, so the retriever returns
        # every matching chunk regardless of which tenant or scope owns it.
        chunks = self._world.rag_retriever(query, top_k or 5, None)
        return {"status": "OK", "chunks": chunks}


UNGUARDED_TOOL_CLASSES: tuple[type[_UnguardedTool], ...] = (
    UnguardedDetectTool,
    UnguardedEvaluatePolicyTool,
    UnguardedSanitizeTextTool,
    UnguardedScanFileTool,
    UnguardedScanDirectoryTool,
    UnguardedReadFileTool,
    UnguardedSanitizeFileTool,
    UnguardedVerifyFileTool,
    UnguardedLLMCallTool,
    UnguardedHTTPPostTool,
    UnguardedSendMessageTool,
    UnguardedQueryDatabaseTool,
    UnguardedRetrieveRAGTool,
)


def build_unguarded_tools(
    *,
    world: ScenarioWorld,
    baseline: BaselineConfig,
    detector: Any,
    transformer: Any,
    capture: BaselineCapture,
) -> list[Tool]:
    return [
        tool_class(world=world, baseline=baseline, detector=detector, transformer=transformer, capture=capture)
        for tool_class in UNGUARDED_TOOL_CLASSES
    ]


__all__ = ["UNGUARDED_TOOL_CLASSES", "UNSUPPORTED", "build_unguarded_tools"]
