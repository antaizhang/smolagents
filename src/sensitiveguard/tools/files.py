"""Path-scoped file discovery, scanning, reading and remediation tools."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from sensitiveguard.models import Action, DecisionSet, GuardStage, GuardStatus, PolicyDecision
from sensitiveguard.runtime.error_model import AuthorizationError, SensitiveGuardError

from .base import SensitiveGuardTool


_REMEDIATION_ACTIONS = {
    "NAME": Action.PSEUDONYMIZE,
    "ADDRESS": Action.GENERALIZE,
    "MOBILE": Action.MASK,
    "TEL": Action.MASK,
    "FAX": Action.MASK,
    "EMAIL": Action.MASK,
    "IDCARD": Action.MASK,
    "PASSPORTID": Action.MASK,
    "DRIVERID": Action.MASK,
    "INSURANCEID": Action.MASK,
    "HEALTHCARD": Action.MASK,
    "RESIDENCEID": Action.MASK,
    "MILITARYID": Action.MASK,
    "TAXID": Action.MASK,
    "VISAAUTH": Action.MASK,
    "SOCIALID": Action.MASK,
    "BANKACCOUNT": Action.TOKENIZE,
    "FINACCOUNT": Action.TOKENIZE,
    "PASSWD": Action.REDACT,
    "API_KEY": Action.REDACT,
    "ACCESS_TOKEN": Action.REDACT,
    "JWT": Action.REDACT,
    "PRIVATE_KEY": Action.REDACT,
}
_CRITICAL_RAW_LABELS = {
    "ACCESS_TOKEN",
    "API_KEY",
    "BANKACCOUNT",
    "FINACCOUNT",
    "IDCARD",
    "JWT",
    "PASSWD",
    "PRIVATE_KEY",
}


def _is_safe_representation(value: str) -> bool:
    return bool(
        re.fullmatch(r"\[REDACTED:[A-Z0-9_]+\]", value)
        or re.fullmatch(r"[A-Z0-9_]+_TOKEN_[A-F0-9]+", value)
        or re.fullmatch(r"[A-Za-z0-9+@._:/-]*\*+[A-Za-z0-9+@._:/-]*", value)
    )


class FilePrivacyService:
    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        max_file_bytes: int = 5_000_000,
        max_files: int = 1_000,
    ) -> None:
        self.gateway = gateway
        self.context = context
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    def _safe_display_path(self, value: str | Path) -> str:
        guarded = self.gateway.guard_text(
            str(value),
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name="file_path_display",
            record_disclosure=False,
        )
        return str(guarded.content) if guarded.allowed else "[WITHHELD_PATH]"

    def _read_text(self, path: str | Path) -> tuple[Path, str]:
        resolved = self.gateway.authorization.authorize_path(path, must_exist=True)
        descriptor = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(resolved, flags)
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise AuthorizationError("The protected path is not a regular file.")
            if file_stat.st_size > self.max_file_bytes:
                raise AuthorizationError("The protected file exceeds the configured size limit.")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = None
                return resolved, handle.read()
        except UnicodeDecodeError as error:
            raise AuthorizationError("Binary or non-UTF-8 files are not scanned as clean text.") from error
        except OSError as error:
            raise AuthorizationError("The protected file could not be opened without following links.") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def scan(self, path: str | Path) -> dict[str, Any]:
        try:
            resolved, content = self._read_text(path)
            detection = self.gateway.detector.detect(content, context=self.context)
            self.gateway.audit_logger.log(
                run_id=self.context.run_id,
                event_type="file_scan",
                stage=GuardStage.DATA_ACQUISITION,
                tool="scan_file",
                destination="internal_file",
                detection=detection,
                decisions=DecisionSet(),
                status=GuardStatus.ALLOWED,
            )
            return {
                "status": "SCANNED",
                "file": self._safe_display_path(resolved.name),
                "size_bytes": len(content.encode("utf-8")),
                **detection.to_dict(),
            }
        except SensitiveGuardError as error:
            return {
                "status": "SKIPPED",
                "file": self._safe_display_path(Path(path).name),
                "reason": error.public_message,
            }
        except Exception:
            return {
                "status": "INCOMPLETE",
                "file": self._safe_display_path(Path(path).name),
                "reason": "Sensitive detection failed; the file was not classified as clean.",
            }

    def scan_directory(self, path: str | Path) -> dict[str, Any]:
        try:
            root = self.gateway.authorization.authorize_path(path, must_exist=True)
        except SensitiveGuardError as error:
            return {"status": "BLOCKED", "reason": error.public_message, "files": []}
        if not root.is_dir():
            return {"status": "BLOCKED", "reason": "The protected path is not a directory.", "files": []}

        results: list[dict[str, Any]] = []
        candidates = sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root)))
        truncated = False
        for candidate in candidates:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if len(results) >= self.max_files:
                truncated = True
                break
            result = self.scan(candidate)
            result["file"] = self._safe_display_path(candidate.relative_to(root))
            results.append(result)

        aggregate: dict[str, int] = {}
        incomplete = False
        for result in results:
            incomplete = incomplete or result["status"] not in {"SCANNED"}
            for label, count in result.get("counts", {}).items():
                aggregate[label] = aggregate.get(label, 0) + count
        return {
            "status": "INCOMPLETE" if incomplete or truncated else "SCANNED",
            "directory": self._safe_display_path(root.name),
            "file_count": len(results),
            "truncated": truncated,
            "counts": dict(sorted(aggregate.items())),
            "files": results,
        }

    def safe_read(self, path: str | Path) -> dict[str, Any]:
        try:
            resolved, content = self._read_text(path)
        except SensitiveGuardError as error:
            return {"status": "BLOCKED", "reason": error.public_message}
        result = self.gateway.guard_text(
            content,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name="safe_read_file",
            record_disclosure=False,
        )
        payload = result.to_dict(include_content=result.allowed)
        payload["file"] = self._safe_display_path(resolved.name)
        payload["privacy_actions"] = list(result.decisions.actions)
        return payload

    def sanitize(self, source: str | Path, destination: str | Path, *, strategy: str) -> dict[str, Any]:
        if strategy.lower() != "policy":
            return {"status": "BLOCKED", "reason": "Only the host policy remediation strategy is supported."}
        try:
            source_path, destination_path = self.gateway.authorization.authorize_copy(source, destination)
            if destination_path.exists():
                raise AuthorizationError("Refusing to overwrite an existing destination file.")
            _, content = self._read_text(source_path)
            detection = self.gateway.detector.detect(content, context=self.context)
            decisions = DecisionSet(
                decisions=tuple(
                    PolicyDecision(
                        finding=finding,
                        action=_REMEDIATION_ACTIONS.get(finding.label, Action.REDACT),
                        reason="Host remediation policy for sanitized artifacts",
                        policy_id="FILE-REMEDIATE-001",
                        severity=finding.severity,
                        allowed_after_transform=True,
                        necessary=False,
                    )
                    for finding in detection.findings
                )
            )
            sanitized = self.gateway.transformer.apply(content, decisions, run_id=self.context.run_id)
            residual_originals = [
                decision.finding.label
                for decision in decisions.decisions
                if decision.finding.value and decision.finding.value in sanitized
            ]
            if residual_originals:
                return {
                    "status": "BLOCKED",
                    "reason": "Transformation verification failed; no output was written.",
                    "residual_labels": sorted(set(residual_originals)),
                }
            verification = self.gateway.detector.detect(sanitized, context=self.context)
            residual_findings = tuple(
                finding
                for finding in verification.findings
                if finding.label in _CRITICAL_RAW_LABELS and not _is_safe_representation(finding.value)
            )
            residual_critical = sorted({finding.label for finding in residual_findings})
            if residual_critical:
                return {
                    "status": "BLOCKED",
                    "reason": "Critical raw identifiers remain after remediation; no output was written.",
                    "residual_labels": residual_critical,
                }
            self._write_new_file(destination_path, sanitized)
            try:
                self.gateway.audit_logger.log(
                    run_id=self.context.run_id,
                    event_type="file_remediation",
                    stage=GuardStage.TOOL_OUTPUT,
                    tool="sanitize_file",
                    destination="sanitized_artifact",
                    detection=detection,
                    decisions=decisions,
                    status=GuardStatus.TRANSFORMED,
                    reason="A separate sanitized artifact was created and verified.",
                )
            except Exception:
                # This output was created by the current call and contains only
                # transformed representations; remove it if mandatory audit
                # persistence failed so the workflow remains transactional.
                destination_path.unlink(missing_ok=True)
                raise
            return {
                "status": "SANITIZED",
                "source": self._safe_display_path(source_path.name),
                "output": self._safe_display_path(destination_path.name),
                "detected": detection.counts(),
                "privacy_actions": list(decisions.actions),
                "verification": "PASS",
                "remaining_raw": {
                    label: sum(1 for finding in residual_findings if finding.label == label)
                    for label in residual_critical
                },
            }
        except SensitiveGuardError as error:
            return {"status": "BLOCKED", "reason": error.public_message}
        except Exception:
            return {"status": "FAILED", "reason": "The sanitized copy could not be created safely."}

    @staticmethod
    def _write_new_file(destination: Path, content: str) -> None:
        destination.parent.mkdir(parents=False, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".sensitiveguard-", dir=destination.parent, text=True)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            # link() provides create-if-absent semantics; it cannot silently
            # replace an unrelated file created during the remediation run.
            os.link(temporary_path, destination)
        finally:
            temporary_path.unlink(missing_ok=True)

    def verify(self, path: str | Path) -> dict[str, Any]:
        result = self.scan(path)
        if result["status"] != "SCANNED":
            return {**result, "verification": "INCOMPLETE"}
        try:
            _, content = self._read_text(path)
            detection = self.gateway.detector.detect(content, context=self.context)
        except Exception:
            return {**result, "verification": "INCOMPLETE"}
        raw_critical = [
            finding
            for finding in detection.findings
            if finding.label in _CRITICAL_RAW_LABELS and not _is_safe_representation(finding.value)
        ]
        critical = {
            label: sum(1 for finding in raw_critical if finding.label == label)
            for label in sorted({finding.label for finding in raw_critical})
        }
        safe_representations = sum(
            1
            for finding in detection.findings
            if finding.label in _CRITICAL_RAW_LABELS and _is_safe_representation(finding.value)
        )
        return {
            **result,
            "verification": "FAIL" if critical else "PASS",
            "critical_remaining": critical,
            "recognized_safe_representations": safe_representations,
        }


class ScanFileTool(SensitiveGuardTool):
    name = "scan_file"
    description = "Scan one authorized UTF-8 file and return label counts without raw values."
    inputs = {"path": {"type": "string", "description": "Path under an authorized root."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, service: FilePrivacyService) -> None:
        super().__init__(gateway=service.gateway, context=service.context)
        self.service = service

    def forward(self, path: str) -> dict[str, Any]:
        return self.service.scan(path)


class ScanDirectoryTool(SensitiveGuardTool):
    name = "scan_directory"
    description = "Recursively scan authorized text files and return a privacy-risk inventory."
    inputs = {"path": {"type": "string", "description": "Directory under an authorized root."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, service: FilePrivacyService) -> None:
        super().__init__(gateway=service.gateway, context=service.context)
        self.service = service

    def forward(self, path: str) -> dict[str, Any]:
        return self.service.scan_directory(path)


class SafeReadFileTool(SensitiveGuardTool):
    name = "safe_read_file"
    description = "Read an authorized file and expose only a policy-approved observation."
    inputs = {"path": {"type": "string", "description": "Path under an authorized root."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, service: FilePrivacyService) -> None:
        super().__init__(gateway=service.gateway, context=service.context)
        self.service = service

    def forward(self, path: str) -> dict[str, Any]:
        return self.service.safe_read(path)


class SanitizeFileTool(SensitiveGuardTool):
    name = "sanitize_file"
    description = "Create a new policy-sanitized copy; never overwrite the source or an existing output."
    inputs = {
        "input": {"type": "string", "description": "Authorized source file."},
        "output": {"type": "string", "description": "New output path under an authorized root."},
        "strategy": {"type": "string", "description": "Must be 'policy'."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, service: FilePrivacyService) -> None:
        super().__init__(gateway=service.gateway, context=service.context)
        self.service = service

    def forward(self, input: str, output: str, strategy: str) -> dict[str, Any]:
        return self.service.sanitize(input, output, strategy=strategy)


class RemediateSensitiveFileTool(SanitizeFileTool):
    name = "remediate_sensitive_file"
    description = "Create and verify a new policy-remediated copy of an authorized file."


class VerifySanitizedFileTool(SensitiveGuardTool):
    name = "verify_sanitized_file"
    description = "Verify that a sanitized file contains no raw critical identifier or reusable secret."
    inputs = {"path": {"type": "string", "description": "Sanitized file to verify."}}
    output_type = "object"
    handles_sensitive_input = True

    def __init__(self, *, service: FilePrivacyService) -> None:
        super().__init__(gateway=service.gateway, context=service.context)
        self.service = service

    def forward(self, path: str) -> dict[str, Any]:
        return self.service.verify(path)
