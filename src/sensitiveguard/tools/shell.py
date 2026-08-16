"""A structured process-capability tool; intentionally not a general shell."""

from __future__ import annotations

import re
import secrets
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from sensitiveguard.models import DecisionSet, DetectionResult, GuardStage, GuardStatus
from sensitiveguard.runtime.authorization import AuthorizationPolicy
from sensitiveguard.runtime.command import (
    AuthorizedCommand,
    CommandAuthorizer,
    CommandCapability,
    CommandExecutionResult,
    CommandExecutor,
    CommandParser,
    fingerprint_command,
)
from sensitiveguard.runtime.error_model import SensitiveGuardError

from .base import SensitiveGuardTool


_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_OTHER = re.compile(r"\x1b[@-_]")


class SafeRunCommandTool(SensitiveGuardTool):
    """Run one exact host capability through an injected networkless executor.

    ``argv`` is a JSON array, never a command string.  The tool contains no
    subprocess implementation; a host must explicitly inject an executor that
    consumes :class:`~sensitiveguard.runtime.command.AuthorizedCommand`.
    """

    name = "safe_run_command"
    description = (
        "Run one host-defined, networkless process capability with structured argv. "
        "Shell syntax, expansion, pipes, redirection and arbitrary executables are forbidden."
    )
    inputs = {
        "capability": {
            "type": "string",
            "description": "Host-defined capability identifier; never an executable or shell command.",
        },
        "argv": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Structured argument tokens matching the capability's exact grammar.",
        },
        "cwd": {
            "type": "string",
            "description": "Optional authorized working directory; shell expansion is forbidden.",
            "nullable": True,
        },
    }
    output_type = "object"
    # Generic input transformation could rewrite a path or control token.  This
    # tool performs its own grammar-aware input guard before calling the host.
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        authorization: AuthorizationPolicy,
        capabilities: Mapping[str, CommandCapability] | Iterable[CommandCapability],
        executor: CommandExecutor,
        parser: CommandParser | None = None,
        fingerprint_key: bytes | None = None,
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._tracks_execution_outcome = True
        if not isinstance(authorization, AuthorizationPolicy):
            raise TypeError("SafeRunCommandTool requires an AuthorizationPolicy")
        execute = getattr(executor, "execute", None)
        if not callable(execute):
            raise TypeError("SafeRunCommandTool requires an executor with execute(command)")
        key = secrets.token_bytes(32) if fingerprint_key is None else fingerprint_key
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("Command fingerprint key must contain at least 16 bytes")
        self.authorization = authorization
        self.authorizer = CommandAuthorizer(capabilities, authorization)
        self.executor = executor
        self.parser = parser or CommandParser()
        self._fingerprint_key = key

    def forward(self, capability: str, argv: list[str], cwd: str | None = None) -> dict[str, Any]:
        self.reset_execution_outcome()
        command: AuthorizedCommand | None = None
        fingerprint: str | None = None
        try:
            # Direct Tool use must enforce the same host gate as Agent use.
            self.authorization.authorize_tool(self.name)
            request = self.parser.parse(capability, argv, cwd)
            command = self.authorizer.authorize(request)
            fingerprint = fingerprint_command(self._fingerprint_key, command)
        except (SensitiveGuardError, TypeError, ValueError):
            self._audit(
                event_type="command_preflight",
                status=GuardStatus.BLOCKED,
                policy_id="command:v1",
                fingerprint=None,
            )
            return self.safe_block("The structured command is outside the host-authorized capability.")

        guarded_input = self._guard_data_arguments(command)
        if guarded_input is None:
            self._audit(
                event_type="command_preflight",
                status=GuardStatus.BLOCKED,
                policy_id=f"command:{command.capability.name}",
                fingerprint=fingerprint,
            )
            return self.safe_block("The command data arguments could not be inspected safely.")
        if not guarded_input.allowed:
            self._audit(
                event_type="command_preflight",
                status=guarded_input.status,
                policy_id=f"command:{command.capability.name}",
                fingerprint=fingerprint,
                detection=guarded_input.detection,
                decisions=guarded_input.decisions,
            )
            return self.result_payload(guarded_input)

        data_indices = command.data_argument_indices
        safe_values = guarded_input.content
        original_values = [command.argv[index] for index in data_indices]
        # Rewriting a command argument can change the operation's semantics and
        # can invalidate the host grammar.  Sensitive command-line data is thus
        # denied rather than silently executing a transformed request.
        if (
            not isinstance(safe_values, list)
            or len(safe_values) != len(data_indices)
            or safe_values != original_values
        ):
            self._audit(
                event_type="command_preflight",
                status=GuardStatus.BLOCKED,
                policy_id=f"command:{command.capability.name}",
                fingerprint=fingerprint,
                detection=guarded_input.detection,
                decisions=guarded_input.decisions,
            )
            return self.safe_block("Sensitive values cannot be placed in process arguments.")

        if not self._audit(
            event_type="command_preflight",
            status=GuardStatus.ALLOWED,
            policy_id=f"command:{command.capability.name}",
            fingerprint=fingerprint,
            detection=guarded_input.detection,
            decisions=guarded_input.decisions,
        ):
            return self.safe_block("Command audit persistence failed; execution was denied.")

        execution_result: CommandExecutionResult | None = None
        execution_failed = False
        try:
            self.mark_execution_started()
            execution_result = self.executor.execute(command)
            if not isinstance(execution_result, CommandExecutionResult):
                execution_failed = True
            else:
                self.mark_execution_completed()
        except Exception:
            # Do not retain or chain the provider exception. It may contain argv,
            # file contents or raw output from the protected process.
            execution_failed = True

        if execution_failed or execution_result is None:
            failed_policy_id = f"command:{command.capability.name}"
            self._audit(
                event_type="command_result",
                status=GuardStatus.BLOCKED,
                policy_id=failed_policy_id,
                fingerprint=fingerprint,
            )
            command = None
            return self.safe_block("The protected command executor failed.")

        return self._guard_execution_result(command, execution_result, fingerprint)

    def _guard_data_arguments(self, command: AuthorizedCommand) -> Any | None:
        values = [command.argv[index] for index in command.data_argument_indices]
        try:
            return self.gateway.guard_payload(
                values,
                self.context,
                GuardStage.TOOL_INPUT,
                destination="local_process",
                tool_name=self.name,
                record_disclosure=False,
            )
        except Exception:
            return None

    def _guard_execution_result(
        self,
        command: AuthorizedCommand,
        result: CommandExecutionResult,
        fingerprint: str,
    ) -> dict[str, Any]:
        policy_id = f"command:{command.capability.name}"
        if result.timed_out or result.output_overflow:
            self._audit(
                event_type="command_result",
                status=GuardStatus.BLOCKED,
                policy_id=policy_id,
                fingerprint=fingerprint,
            )
            return self.safe_block("The command exceeded its protected execution limits.")

        try:
            stdout_bytes = result.stdout.encode("utf-8") if isinstance(result.stdout, str) else result.stdout
            stderr_bytes = result.stderr.encode("utf-8") if isinstance(result.stderr, str) else result.stderr
            if len(stdout_bytes) + len(stderr_bytes) > command.capability.max_output_bytes:
                raise ValueError("output limit")
            stdout = self._canonicalize_output(stdout_bytes.decode("utf-8", errors="strict"))
            stderr = self._canonicalize_output(stderr_bytes.decode("utf-8", errors="strict"))
        except (UnicodeError, ValueError):
            self._audit(
                event_type="command_result",
                status=GuardStatus.BLOCKED,
                policy_id=policy_id,
                fingerprint=fingerprint,
            )
            return self.safe_block("Command output was not safe bounded UTF-8 text.")

        try:
            guarded_output = self.gateway.guard_payload(
                {"stdout": stdout, "stderr": stderr},
                self.context,
                GuardStage.TOOL_OUTPUT,
                destination="agent_memory",
                tool_name=self.name,
                record_disclosure=False,
            )
        except Exception:
            self._audit(
                event_type="command_result",
                status=GuardStatus.BLOCKED,
                policy_id=policy_id,
                fingerprint=fingerprint,
            )
            return self.safe_block("Command output inspection failed; the output was withheld.")

        if not guarded_output.allowed:
            self._audit(
                event_type="command_result",
                status=guarded_output.status,
                policy_id=policy_id,
                fingerprint=fingerprint,
                detection=guarded_output.detection,
                decisions=guarded_output.decisions,
            )
            return self.result_payload(guarded_output)

        content = guarded_output.content
        if (
            not isinstance(content, dict)
            or not isinstance(content.get("stdout"), str)
            or not isinstance(content.get("stderr"), str)
        ):
            self._audit(
                event_type="command_result",
                status=GuardStatus.BLOCKED,
                policy_id=policy_id,
                fingerprint=fingerprint,
            )
            return self.safe_block("Command output inspection returned an invalid result.")

        if not self._audit(
            event_type="command_result",
            status=guarded_output.status,
            policy_id=policy_id,
            fingerprint=fingerprint,
            detection=guarded_output.detection,
            decisions=guarded_output.decisions,
        ):
            return self.safe_block("Command audit persistence failed; the output was withheld.")

        return {
            "status": guarded_output.status.value,
            "capability": command.capability.name,
            "exit_code": result.exit_code,
            "stdout": content["stdout"],
            "stderr": content["stderr"],
            "duration_ms": result.duration_ms,
            "privacy_actions": list(guarded_output.decisions.actions),
        }

    def _audit(
        self,
        *,
        event_type: str,
        status: GuardStatus,
        policy_id: str,
        fingerprint: str | None,
        detection: DetectionResult | None = None,
        decisions: DecisionSet | None = None,
    ) -> bool:
        metadata = {"policy_id": policy_id}
        if fingerprint is not None:
            metadata["value_fingerprint"] = fingerprint
        try:
            self.gateway.audit_logger.log(
                run_id=getattr(self.context, "run_id"),
                event_type=event_type,
                stage=(GuardStage.TOOL_INPUT if event_type == "command_preflight" else GuardStage.TOOL_OUTPUT),
                tool=self.name,
                destination=("local_process" if event_type == "command_preflight" else "agent_memory"),
                detection=detection or DetectionResult(),
                decisions=decisions or DecisionSet(),
                status=status,
                reason=None,
                metadata=metadata,
            )
        except Exception:
            return False
        return True

    @staticmethod
    def _canonicalize_output(value: str) -> str:
        value = _ANSI_OSC.sub("", value)
        value = _ANSI_CSI.sub("", value)
        value = _ANSI_OTHER.sub("", value)
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        return "".join(
            character
            for character in value
            if character in {"\n", "\t"} or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
        )


# Compatibility names for hosts that prefer a shorter class name.  All aliases
# retain the safe_run_command tool name and structured-only behavior.
SafeCommandTool = SafeRunCommandTool
SafeShellTool = SafeRunCommandTool


__all__ = ["SafeCommandTool", "SafeRunCommandTool", "SafeShellTool"]
