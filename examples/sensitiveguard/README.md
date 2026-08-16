# SensitiveGuard examples and secure host wiring

Run the fully offline demo from the repository root:

```bash
PYTHONPATH=src python examples/sensitiveguard/offline_demo.py
```

`offline_demo.py` exercises three acceptance paths:

1. scan a directory, create and verify a separate sanitized copy, and keep the source byte-for-byte unchanged;
2. pass purchase data through `safe_llm_call` and inspect the exact minimized prompt received by an injected fake client;
3. simulate an indirect prompt-injection exfiltration attempt and prove that the injected HTTP transport is called zero times.

The demo itself stays small, but `SensitiveGuardRuntime.create()` now assembles all seven runtime controls used by an
Agent:

| # | Control | Runtime object / integration point |
| --- | --- | --- |
| 1 | Privacy route | `PrivacyRouter`, `EndpointDescriptor`, optional `model_endpoint_id` |
| 2 | Security review | `SecurityReviewEngine` and one-use `ExecutionPermitStore` |
| 3 | Tool constraints | `CapabilityManifestRegistry`; tools registered by `create_agent()` |
| 4 | Structured commands | `SafeRunCommandTool`, host `CommandCapability`, host-injected `CommandExecutor` |
| 5 | Sensitive detection | Regex + Secret + Injection + normalization + encoded payload; optional local GLiNER |
| 6 | Raw-free lineage | `LineageTracker`, automatic Gateway records and Tool PREPARED/terminal states |
| 7 | Intent consistency | signed `IntentSpec`, `IntentResolver`, `IntentGuard` |

The protected Agent tool path is:

```text
trusted PrivacyContext -> signed intent -> manifest + route -> security review
-> lineage PREPARED -> one-use permit -> Safe Tool -> output guard
-> lineage COMMITTED/ABORTED/INDETERMINATE -> sanitized memory
```

## Default-deny setup

Treat every value below as trusted host configuration, never as a value chosen by the model:

```python
from sensitiveguard import PrivacyContext, SensitiveGuardRuntime

context = PrivacyContext(
    task="query approved purchase fields and summarize them",
    purpose="purchase_behavior_analysis",
    destination="external_llm",
    trust_level="untrusted",
    required_fields=("purchase_history",),
    forbidden_fields=("PASSWD",),
    allowed_scope=("purchase_history",),
    allowed_operations=("QUERY", "ANALYZE", "SUMMARIZE"),
    allowed_capabilities=("safe_query_database", "safe_llm_call"),
    allowed_effects=("READ", "MODEL", "EXTERNAL"),
    allowed_destinations=("database", "external_llm", "internal", "local", "requester"),
    denied_capabilities=("raw_shell", "raw_http_post"),
)

runtime = SensitiveGuardRuntime.create(
    context,
    allowed_database_tables={"customers": ("customer_id", "purchase_history")},
    known_external_destinations=("external_llm", "requester"),
)
```

Unknown external destinations are blocked by policy (`SG-EXTERNAL-DEFAULT-DENY`). Unknown endpoints, external fallback,
unregistered or changed tool implementations, out-of-intent effects, permit mismatch/replay/expiry, unavailable lineage,
and audit failure are also denied. Prompt-injection taint is inherited through lineage and blocks external/network/message
effects even when the immediate arguments look clean. The current Agent review is deliberately more conservative: any
tainted artifact in the active run report taints a proposed external call.

`allowed_*` defaults retain conservative rule inference for compatibility. Production hosts should set them explicitly.
Task wording alone never grants `EXECUTE` or `DELETE`; those operations and their capabilities/effects require explicit host
authorization.

## Detector and route examples

The default detector remains offline and does not download a model:

```python
detection = runtime.detector.detect("text to inspect", context)
print(detection.labels, detection.counts())
```

It combines canonical Regex/Secret/Prompt-Injection detection with NFKC/zero-width normalization and bounded, single-layer
URL-percent/Base64/hex decoding. The public `DetectionResult.to_dict()` omits raw finding values. GLiNER is added only when a
preloaded model, a local-only model path, or a local factory is passed to `SensitiveGuardRuntime.create(...)`.

Model endpoints are descriptors, not clients:

```python
from sensitiveguard import EndpointDescriptor, Severity

endpoints = (
    EndpointDescriptor(
        endpoint_id="local-model",
        destination="local",
        trust_level="internal",
        is_local=True,
        operations=("model_inference",),
        max_sensitivity=Severity.CRITICAL,
        priority=10,
    ),
)
runtime = SensitiveGuardRuntime.create(context, endpoints=endpoints)
route = runtime.privacy_router.route_model(
    detection,
    operation="model_inference",
    preferred_endpoint="local-model",
    allow_external_fallback=False,
)
```

The host maps `route.endpoint_id` to a real client. Passing `model_endpoint_id=route.endpoint_id` and
`model_destination=route.destination` to `runtime.create_agent(...)` makes the Agent re-check that route for the actual
guarded task. The router never turns an endpoint ID into a URL and never silently substitutes an external client.

## Intent, security review, and lineage

`runtime.create_agent(model, tools=tools)` registers the exact tool classes/schemas as capability manifests and applies
security review automatically before every tool execution. A direct call to `tool.forward(...)` still uses that Safe Tool's
Gateway guards, but it does **not** automatically run the Agent's intent/manifest/permit orchestration. A non-Agent host must
explicitly call `security_reviewer.preflight(...)`, then `consume(...)`, and finally `complete(...)` or `fail(...)`.

The Agent derives authority only from the host-created `PrivacyContext`. The string passed to `agent.run(task)` is untrusted
workload data: it is guarded before model I/O and can never add an operation, capability, effect, destination, or recipient.
Do not build an authorization context directly from an end-user prompt; set explicit host-owned `allowed_*`/`denied_*` ceilings.

You can inspect the raw-free intent and lineage state without exposing the task or payload:

```python
intent = runtime.intent_resolver.resolve(context)
child = runtime.intent_resolver.narrow(
    intent,
    allowed_operations=("QUERY",),
    allowed_capabilities=("safe_query_database",),
    allowed_effects=("READ",),
    allowed_fields=("purchase_history",),
    allowed_destinations=("database",),
)
assert runtime.intent_guard.validate_plan(intent, child).allowed

report = runtime.lineage_tracker.report(context)
assert report.chain_valid
if report.nodes:
    ancestors = runtime.lineage_tracker.ancestors(report.nodes[-1].artifact_id, context)
```

Lineage nodes/events are immutable and store only run-scoped keyed HMAC fingerprints, labels, taints, opaque references,
parent IDs, and hash-chain values. They never store payload, prompt, path, URL, recipient, or entity text. Gateway guards
record parent propagation automatically. Tool security review uses `PREPARED -> COMMITTED`; a proven no-call uses `ABORTED`,
while a timeout or unknown external outcome must use `INDETERMINATE`.

## `safe_run_command` is not a shell

SensitiveGuard intentionally ships **no command executor**. The only command API accepts a named host capability and a JSON
`argv` token array. It never accepts or parses a raw shell string.

```python
from sensitiveguard import CommandArgumentRule, CommandCapability, PrivacyContext, SensitiveGuardRuntime

command_context = PrivacyContext(
    task="count lines in one authorized local report",
    purpose="local_report_inspection",
    destination="local_process",
    trust_level="internal",
    allowed_scope=("report",),
    allowed_operations=("EXECUTE",),
    allowed_capabilities=("safe_run_command",),
    allowed_effects=("EXECUTE", "READ"),
    allowed_destinations=("local_process", "internal", "requester"),
)
command_runtime = SensitiveGuardRuntime.create(
    command_context,
    allowed_roots=("/data/reports",),
)

capability = CommandCapability(
    name="count_report_lines",
    executable="/usr/bin/wc",
    argument_rules=(
        CommandArgumentRule.fixed("mode", "-l"),
        CommandArgumentRule.read_path("report"),
    ),
    timeout_seconds=5,
    max_output_bytes=16_384,
    network_allowed=False,
)

tools = command_runtime.build_tools(
    command_capabilities=(capability,),
    command_executor=host_sandbox_executor,
)
```

The model-visible call remains structured:

```json
{"capability": "count_report_lines", "argv": ["-l", "/data/reports/approved.txt"], "cwd": null}
```

`host_sandbox_executor` must be injected by trusted host code and implement
`execute(command: AuthorizedCommand) -> CommandExecutionResult`. It must execute `command.full_argv` as an argv sequence in
a networkless OS/container sandbox, never join it into a string, never use `shell=True`, and enforce closed inherited file
descriptors, executable identity/digest, timeout, and output limits. It must not include argv or raw output in exceptions.

Capabilities and an executor must be configured together. `/bin/sh`, interpreters, network-capable binaries, shell syntax,
pipes, redirection, expansion, globbing, URLs, out-of-root paths, sensitive argv, and unsafe/binary/unbounded output are denied.
Do not add a compatibility layer that converts `"wc -l file"` into argv; raw shell strings are outside the API by design.

## Trusted client boundary

Real LLM, HTTP, database, RAG, message/email, MCP, and command-executor clients must be injected by trusted host code. Never
expose those raw clients as smolagents tools. HTTP transports must prevent redirect/DNS-rebinding bypass, and command execution
must have OS-level sandboxing; SensitiveGuard's application checks do not replace network, filesystem, database, or process
isolation.

## Benchmark suite

The demos show three paths. The benchmark suite measures all eight of them across four baselines:

```bash
PYTHONPATH=src python -m sensitiveguard.eval
```

This runs 26 scenarios under B0 (raw smolagents), B1 (detection only), B2 (uniform redaction) and B3 (full
SensitiveGuard), prints the comparison table, and exits non-zero if a graded baseline misses the acceptance bar — so
the same command works as a CI gate. It needs no model and no network, and finishes in a few seconds.

Useful flags:

```bash
python -m sensitiveguard.eval --benchmark PII-Injection --baseline B0 --baseline B3
python -m sensitiveguard.eval --json report.json --no-gate
python -m sensitiveguard.eval --dataset my_scenarios.jsonl
```

Leakage is judged by searching recorded sink traffic for the literal canary values the harness planted, not by asking
the detector under test. A value the detector misses is therefore reported as a leak rather than hidden by the miss.

For the complete Chinese walkthrough and the manual review/lineage protocols, see
`docs/source/zh/tutorials/sensitiveguard.md`.
