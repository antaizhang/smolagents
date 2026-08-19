"""Four inspectable probes over the real SensitiveGuard runtime.

Every probe is offline and side-effect free: no model download, no outbound
socket, and **no subprocess** — the command probe injects a simulated executor,
so nothing on the demo host is ever run.  The "external" LLM, HTTP and message
clients are recording fakes, which lets a demo prove a negative: that a blocked
call reached the wire zero times.

Probes
------
``detect_probe``      敏感数据识别: labels, severities, and the rewritten text.
``command_probe``     外发命令检测: static egress scoring of a proposed shell
                      string, plus which layer of the real, default-deny
                      command API refuses the same request.
``structured_probe``  the authorized path: a host-declared capability invoked
                      with a token array through ``safe_run_command``.
``egress_probe``      外发通道拦截: run a real Safe*Tool against a recording
                      transport and report whether payload values crossed it.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sensitiveguard import (
    CommandArgumentRule,
    CommandCapability,
    CommandExecutionResult,
    EgressCommandInspector,
    PrivacyContext,
    SensitiveGuardRuntime,
)
from sensitiveguard.runtime.command import AuthorizedCommand, CommandParser


ALLOWED_HTTP_HOSTS = ("reports.internal.example",)
ALLOWED_MESSAGE_RECIPIENTS = ("privacy-officer@internal.example",)
DEMO_CAPABILITY = "count_report_lines"


# ------------------------------------------------------------------ contexts
# Every authorization value below is host configuration.  None of it is ever
# derived from the text a caller submits.


def _detection_context() -> PrivacyContext:
    return PrivacyContext(
        task="inspect submitted text for sensitive data",
        purpose="sensitive_data_inspection",
        requester="demo-operator",
        trust_level="untrusted",
        allowed_scope=("submitted_text",),
        allowed_operations=("ANALYZE",),
        allowed_effects=("READ",),
        allowed_destinations=("internal", "requester"),
        denied_capabilities=("raw_shell", "raw_http_post"),
    )


def _egress_context() -> PrivacyContext:
    return PrivacyContext(
        task="summarize approved purchase fields with an external assistant",
        purpose="purchase_behavior_analysis",
        requester="demo-operator",
        recipient="external-provider",
        destination="external_llm",
        trust_level="untrusted",
        required_fields=("purchase_history",),
        forbidden_fields=("PASSWD",),
        allowed_scope=("purchase_history",),
        allowed_operations=("QUERY", "ANALYZE", "SUMMARIZE"),
        allowed_capabilities=("safe_llm_call", "safe_http_post", "safe_send_message"),
        allowed_effects=("READ", "MODEL", "EXTERNAL"),
        allowed_destinations=("external_llm", "internal", "requester"),
        denied_capabilities=("raw_shell", "raw_http_post"),
    )


def _command_context() -> PrivacyContext:
    return PrivacyContext(
        task="count lines in one authorized local report",
        purpose="local_report_inspection",
        requester="demo-operator",
        destination="local_process",
        trust_level="internal",
        allowed_scope=("report",),
        allowed_operations=("EXECUTE", "ANALYZE"),
        allowed_capabilities=("safe_run_command",),
        allowed_effects=("EXECUTE", "READ"),
        allowed_destinations=("local_process", "internal", "requester"),
        denied_capabilities=("raw_shell", "raw_http_post"),
    )


# --------------------------------------------------------------- fake clients


@dataclass
class RecordingWire:
    """Stands in for every real external client and remembers what it saw."""

    llm_prompts: list[str] = field(default_factory=list)
    http_calls: list[tuple[str, Any]] = field(default_factory=list)
    messages: list[tuple[str, str]] = field(default_factory=list)

    def llm(self, prompt: str) -> str:
        self.llm_prompts.append(prompt)
        return "summary: the customer bought a laptop"

    def http(self, url: str, body: Any) -> dict[str, Any]:
        self.http_calls.append((url, body))
        return {"ok": True}

    def message(self, recipient: str, body: str) -> None:
        self.messages.append((recipient, body))

    def transcript(self) -> list[str]:
        parts = list(self.llm_prompts)
        parts.extend(f"{url} {body}" for url, body in self.http_calls)
        parts.extend(f"{recipient} {body}" for recipient, body in self.messages)
        return parts

    @property
    def call_count(self) -> int:
        return len(self.llm_prompts) + len(self.http_calls) + len(self.messages)


@dataclass
class SimulatedExecutor:
    """A CommandExecutor that records the authorization outcome and runs nothing.

    SensitiveGuard deliberately ships no executor.  A production host injects
    one that spawns ``command.full_argv`` inside a networkless OS sandbox; this
    demo injects a simulation so the box it runs on never executes a process.
    """

    seen: list[tuple[str, ...]] = field(default_factory=list)

    def execute(self, command: AuthorizedCommand) -> CommandExecutionResult:
        self.seen.append(command.full_argv)
        return CommandExecutionResult(exit_code=0, stdout=b"12\n", duration_ms=1.0)


def _tool(tools: list[Any], name: str) -> Any:
    return next(tool for tool in tools if tool.name == name)


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _preview(value: str, limit: int = 160) -> str:
    cleaned = _CONTROL.sub("·", str(value).strip())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


# ---------------------------------------------------------------- 敏感数据识别


def detect_probe(text: str) -> dict[str, Any]:
    """What is in this text, how severe is it, and how does the runtime rewrite it."""
    context = _detection_context()
    runtime = SensitiveGuardRuntime.create(context)
    tools = runtime.build_tools()

    detection = runtime.detector.detect(text, context)
    return {
        "contains_sensitive_data": detection.contains_sensitive_data,
        "labels": list(detection.labels),
        "counts": detection.counts(),
        "severities": sorted({finding.severity.value for finding in detection.findings}),
        "detectors": sorted({finding.detector for finding in detection.findings}),
        "policy": _tool(tools, "evaluate_data_policy")(text=text),
        "masked_text": _content(_tool(tools, "mask_text")(text=text)),
        "redacted_text": _content(_tool(tools, "redact_text")(text=text)),
        "pseudonymized_text": _content(_tool(tools, "pseudonymize_text")(text=text)),
    }


def _content(result: Any) -> Any:
    if isinstance(result, dict):
        for key in ("content", "text", "output"):
            if key in result:
                return result[key]
    return result


# --------------------------------------------------------------- 外发命令检测


def command_probe(command: str, *, allowed_hosts: tuple[str, ...] = ALLOWED_HTTP_HOSTS) -> dict[str, Any]:
    """Score a proposed shell string, then show what the real gate does with it."""
    context = _detection_context()
    runtime = SensitiveGuardRuntime.create(context, allowed_http_hosts=allowed_hosts)
    inspector = EgressCommandInspector(detector=runtime.detector, allowed_hosts=allowed_hosts)
    inspection = inspector.inspect(command, context)

    return {
        "command_preview": _preview(command),
        "inspection": inspection.to_dict(),
        "structured_api": _structured_refusal(command),
        "note": (
            "静态检查是黑名单，只用于告警和审计；真正的执行边界是 CommandAuthorizer 白名单 加宿主注入的沙箱执行器。"
        ),
    }


def _structured_refusal(command: str) -> dict[str, Any]:
    """Report which layer of the structured command API refuses this raw string.

    The structured API takes a capability name plus a token array; handing it
    the tokens of an arbitrary shell string is exactly the request it exists to
    refuse, so this names the refusing layer instead of just saying "denied".
    """
    tokens = command.split()
    if not tokens:
        return {"accepted": False, "refused_by": "CommandParser", "reason": "空命令"}
    capability, argv = tokens[0], tokens[1:]
    try:
        CommandParser().parse(capability, argv)
    except Exception as error:
        return {
            "accepted": False,
            "refused_by": "CommandParser",
            "reason": "令牌未通过结构化校验：shell 元字符、网络标记、控制字符或非法能力名",
            "error": type(error).__name__,
        }
    return {
        "accepted": False,
        "refused_by": "CommandAuthorizer",
        "reason": f"能力名 {capability!r} 不在宿主注册的白名单中，默认拒绝",
    }


# ------------------------------------------------------- 结构化命令（放行路径）


def _demo_workspace() -> Path:
    """Create the fixture tree the authorized command path is allowed to touch."""
    root = Path(tempfile.mkdtemp(prefix="sg-demo-")).resolve()
    report = root / "approved.txt"
    report.write_text("line one\nline two\n", encoding="utf-8")
    # A fixture file that stands in for a host binary.  The injected executor is
    # a simulation, so this file is never executed.
    executable = root / "sg-demo-counter"
    executable.write_bytes(b"offline fixture; the demo executor never runs it\n")
    executable.chmod(0o755)
    return root


def structured_probe(argv: list[str] | None = None, *, capability: str = DEMO_CAPABILITY) -> dict[str, Any]:
    """Invoke the authorized command path with a host-declared capability."""
    root = _demo_workspace()
    context = _command_context()
    runtime = SensitiveGuardRuntime.create(context, allowed_roots=(root,))
    executor = SimulatedExecutor()
    declared = CommandCapability(
        name=DEMO_CAPABILITY,
        executable=root / "sg-demo-counter",
        argument_rules=(
            CommandArgumentRule.fixed("mode", "-l"),
            CommandArgumentRule.read_path("report"),
        ),
        timeout_seconds=5,
        max_output_bytes=16_384,
        network_allowed=False,
    )
    tools = runtime.build_tools(
        command_capabilities=(declared,),
        command_executor=executor,
        command_fingerprint_key=b"offline-demo-fingerprint-key-32b",
    )
    tokens = ["-l", str(root / "approved.txt")] if argv is None else list(argv)
    result = _tool(tools, "safe_run_command")(capability=capability, argv=tokens)
    return {
        "capability": capability,
        "argv": [_preview(token, 80) for token in tokens],
        "tool_result": result,
        "executor_invocations": len(executor.seen),
        "workspace": str(root),
        "declared_grammar": ["-l (固定字面量)", "报告路径 (必须位于授权根目录内且已存在)"],
    }


# --------------------------------------------------------------- 外发通道拦截


def egress_probe(
    channel: str,
    target: str,
    payload: str,
    *,
    allow_private_networks: bool = False,
) -> dict[str, Any]:
    """Run the real Safe*Tool and then inspect the recording wire.

    ``allow_private_networks`` exists only so an offline lab can see the
    delivered path: the allowlisted demo host has no public DNS record, and
    the authorizer fails closed on any host it cannot classify.  Production
    hosts must leave it ``False`` — that check is what stops DNS rebinding
    and SSRF into the internal network.
    """
    channel = (channel or "").strip().lower()
    if channel not in {"llm", "http", "message"}:
        raise ValueError("channel must be one of: llm, http, message")

    context = _egress_context()
    runtime = SensitiveGuardRuntime.create(
        context,
        allowed_http_hosts=ALLOWED_HTTP_HOSTS,
        allow_private_networks=allow_private_networks,
        known_external_destinations=("external_llm", "requester"),
    )
    wire = RecordingWire()
    tools = runtime.build_tools(
        external_llm_client=wire.llm,
        http_transport=wire.http,
        message_sender=wire.message,
        allowed_message_recipients=ALLOWED_MESSAGE_RECIPIENTS,
    )

    if channel == "llm":
        result = _tool(tools, "safe_llm_call")(text=payload, purpose=context.purpose)
    elif channel == "http":
        result = _tool(tools, "safe_http_post")(url=target, body=payload)
    else:
        result = _tool(tools, "safe_send_message")(recipient=target, body=payload)

    transcript = wire.transcript()
    return {
        "channel": channel,
        "target": _preview(target, 80),
        "allow_private_networks": allow_private_networks,
        "tool_result": result,
        "wire_call_count": wire.call_count,
        "wire_transcript": [_preview(item, 240) for item in transcript],
        "leaked_values": leaked_values(payload, transcript),
    }


_TOKEN = re.compile(r"[0-9A-Za-z][0-9A-Za-z@._+-]{7,}")


def leaked_values(payload: str, transcript: list[str]) -> list[str]:
    """Payload tokens that survived into the recorded outbound traffic.

    Leakage is judged by searching the wire for literal payload substrings, not
    by re-running the detector, so a value the detector misses is reported as a
    leak instead of being hidden by the miss.
    """
    if not transcript:
        return []
    joined = "\n".join(transcript)
    return sorted({token for token in _TOKEN.findall(payload) if token in joined})
