# 使用 SensitiveGuard 构建敏感数据安全 Agent

SensitiveGuard 是一个独立于模型的隐私运行时。它把 smolagents 的 `ToolCallingAgent` 用作规划与工具选择层，
把检测、最小化、确定性策略、变换、授权、隐私预算、意图一致性、数据血缘和审计放在模型无法绕过的运行时边界中。

它保护四条通道：

1. 任务和数据获取进入模型之前；
2. Tool 参数进入真实系统之前；
3. Tool observation 写入 Agent Memory 之前；
4. 普通或达到步数上限的最终答案返回之前。

在这四条数据边界之外，当前实现还把每次受保护调用拆成七项可独立检查的能力：

1. **隐私路由**：可信宿主注册 endpoint，本地优先并执行敏感度 ceiling；未知 endpoint 和未显式允许的外部 fallback 拒绝。
2. **安全审查**：Tool 调用先绑定 route、intent、capability manifest、参数、血缘和策略版本，再签发一次性 permit。
3. **工具约束**：只暴露 `SensitiveGuardTool`，manifest 固定实现类型、输入 schema、effects、destination 和每 run 配额。
4. **Shell/命令链路**：仅支持宿主定义的结构化 process capability，不提供通用 shell，也不包含内置 process executor。
5. **敏感检测**：Regex、Secret、Prompt Injection、Unicode 归一化和单层编码检测默认离线组合，GLiNER 可选且仅本地加载。
6. **数据血缘**：使用 run-scoped keyed HMAC 记录无原文 DAG、注入 taint、操作状态和 hash chain。
7. **意图一致性**：把可信 `PrivacyContext` 编译成带版本和期限的签名 `IntentSpec`，计划只能缩权，动作不能扩权或重放。

Agent 中一次 Tool 调用的实际顺序如下。任一阶段异常都不会降级为无保护调用：

```text
可信 PrivacyContext
  -> IntentResolver（签名意图）
  -> CapabilityManifest + PrivacyRouter
  -> IntentGuard + Lineage PREPARED
  -> 一次性 ExecutionPermit
  -> Safe Tool / 宿主 sink
  -> Tool Output Guard
  -> Lineage COMMITTED（或 ABORTED / INDETERMINATE）
  -> Agent Memory
```

## 安装

核心运行时不需要下载模型，默认使用 Regex、Secret、Prompt Injection、Unicode normalization 和 encoded-payload
检测器。GLiNER 是可选依赖：

```bash
pip install -e .
pip install -e '.[sensitiveguard]'  # 仅在需要 GLiNER 时安装
```

生产环境应由运维代码预加载本地 GLiNER 模型，再把模型对象传给 Runtime。默认适配器不会自动从 Hub 下载模型。

## 创建 Runtime

```python
from sensitiveguard import PrivacyContext, SensitiveGuardRuntime

context = PrivacyContext(
    task="分析客户购买品类",
    purpose="purchase_behavior_analysis",
    requester="employee-001",
    recipient="external-provider",
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
    intent_version=1,
)

runtime = SensitiveGuardRuntime.create(
    context,
    allowed_roots=("/data/customer",),
    allowed_http_hosts=("analytics.example",),
    allowed_database_tables={
        "customers": ("customer_id", "purchase_history"),
    },
    default_privacy_budget=100,
    audit_jsonl_path="/var/log/sensitiveguard/audit.jsonl",
)
```

如需加载业务策略，可把 JSON、打包内同等结构的 YAML 文件路径或已解析 mapping 作为
`policy_source=` 传入；Runtime 会校验重复 `policy_id`、Action、stage、风险区间和未知字段，解析失败时不会退回宽松策略。

`purpose`、`destination` 和 `trust_level` 必须由可信宿主创建，不能采用 LLM 在 Tool 参数中自报的值。文件根目录、
HTTP host 和数据库字段也采用显式 allowlist；未知外发目标默认拒绝。

`audit_key`、`lineage_key`、`intent_key`、`routing_key` 和 `execution_permit_key` 未提供时会为当前 Runtime 生成随机 key。
生产部署应从 KMS/HSM 注入用途隔离、可轮换的独立 key，并按 run/保留期管理；不要在日志中记录 key，也不要为不同用途复用同一 key。

`allowed_*` 为空时，意图解析器会为兼容旧调用者，根据可信 `task`/`purpose` 做保守的中英文规则推断；生产环境建议显式填写。
`denied_*` 始终从允许集合中扣除，`("*",)` 表示全部拒绝。`EXECUTE` 和 `DELETE` 不会仅因任务文本中出现“执行”或“删除”而获得授权，
必须由宿主在 `allowed_operations`、`allowed_capabilities` 和 `allowed_effects` 中同时显式声明。`PrivacyContext` 是不可变 dataclass，
运行中需要收窄或改变目的时应创建新的 context/run，而不是让模型修改现有对象。

## 1. 隐私路由

`EndpointDescriptor` 只描述可信宿主注册的 endpoint，不持有 client。`PrivacyRouter` 根据检测到的最高敏感等级、operation、可用性和
`max_sensitivity` 选择 endpoint，并优先满足本地 route。真实 client 仍由宿主通过 `endpoint_id` 查表并注入：

```python
from sensitiveguard import EndpointDescriptor, PrivacyContext, SensitiveGuardRuntime, Severity

endpoints = (
    EndpointDescriptor(
        endpoint_id="local-qwen",
        destination="local",
        trust_level="internal",
        is_local=True,
        operations=("model_inference",),
        max_sensitivity=Severity.CRITICAL,
        priority=10,
    ),
    EndpointDescriptor(
        endpoint_id="external-analysis",
        destination="external_llm",
        trust_level="untrusted",
        is_local=False,
        operations=("model_inference",),
        max_sensitivity=Severity.MEDIUM,
        priority=100,
        allow_fallback=False,
    ),
)

runtime = SensitiveGuardRuntime.create(context, endpoints=endpoints)
detection = runtime.detector.detect("待路由内容", context)
route = runtime.privacy_router.route_model(
    detection,
    operation="model_inference",
    preferred_endpoint="local-qwen",
    allow_external_fallback=False,
)
if not route.allowed:
    raise RuntimeError(route.reason_code)

# host_models 是可信宿主配置；endpoint_id 不能由模型映射到任意 URL。
planner = host_models[route.endpoint_id]
agent = runtime.create_agent(
    planner,
    model_destination=route.destination,
    model_endpoint_id=route.endpoint_id,
)
```

设置 `model_endpoint_id` 后，Agent 会在每次 run 的任务输入经过检测后再次验证 endpoint 和 `model_destination`。如果不设置它，
Runtime 仍保护模型输入，但不会替宿主动态选择模型 client。对 Tool 的 route 则从真实 Safe Tool 和已授权参数推导：例如 HTTP 目标来自
`authorize_url()` 后的 host，消息目标来自精确 recipient allowlist，命令固定为 `local_process`；模型提供的 destination hint 不能把内部
capability 伪装成外部或把外部 sink 伪装成本地。

## 2–3. 安全审查与工具 capability

`SensitiveGuardRuntime.create()` 会创建 `CapabilityManifestRegistry`、`ExecutionPermitStore` 和 `SecurityReviewEngine`；
`runtime.create_agent()` 会注册实际暴露的 tools。Agent 每次调用 Tool 前自动执行：

1. `AuthorizationPolicy.authorize_tool()` 和 manifest 存在性检查；
2. 当前 Tool 类型与 input/output schema 是否仍匹配 manifest；
3. `PrivacyRouter.route_tool()` 的实际 route 是否落在 manifest 和 intent 的 destination 内；
4. operation、capability、effects、fields、recipient、版本、期限和注入血缘是否符合签名 intent；
5. 写入血缘 `PREPARED`，把精确参数、route、recipient、lineage IDs、manifest digest 和 policy version 绑定到一次性 permit；
6. 原子消费 permit 和 per-run 调用配额后才允许调用真实 Tool；输出成功后提交 `COMMITTED`。

permit 过期、重放、参数变化、manifest/schema 变化、route 变化、策略版本变化、审计失败、血缘不可用或配额耗尽都会拒绝调用。
未知 Tool 不能获得外部 route；自定义 Tool 只有在可信宿主将其作为 `SensitiveGuardTool` 暴露并注册后，才会被视作内部 TCB capability。
这并不意味着任意自定义 Tool 自动安全：宿主仍负责其最小权限实现和内部资源隔离。

通过 `runtime.create_agent()` 运行时不需要手工调用 review。若另一个可信编排器直接调用 Safe Tool，必须显式复用同一协议；
只调用 `tool.forward()` 会执行该 Tool 自身的 Gateway guard，但不会自动获得 Agent 的 manifest/intent/permit 编排：

```python
tools = runtime.build_tools(database_executor=read_only_database_executor)
runtime.security_reviewer.register_tools(tools)
intent = runtime.intent_resolver.resolve(context)
tool = next(item for item in tools if item.name == "safe_query_database")
arguments = {"table": "customers", "fields": ["purchase_history"], "filters": {}}

review = runtime.security_reviewer.preflight(tool, arguments, context, intent)
if not review.allowed:
    raise PermissionError(review.code)
if not runtime.security_reviewer.consume(review, tool, arguments, context, intent):
    raise PermissionError("execution permit was rejected")

try:
    output = tool.forward(**arguments)
except Exception:
    # 如果 sink 是否已产生副作用无法证明，必须记录 INDETERMINATE。
    runtime.security_reviewer.fail(review, context, indeterminate=True)
    raise
if not runtime.security_reviewer.complete(review, output, context):
    raise RuntimeError("lineage commit failed; withhold output")
```

不要把 `preflight()` 当成长期授权：只有紧邻真实调用的 `consume()` 才能原子消费一次性 permit。

## 4. `safe_run_command`：结构化 capability，不是 Shell

SensitiveGuard **没有内置命令 executor，也绝不接受 raw shell 字符串**。`safe_run_command` 的输入只能是
`capability: str`、`argv: list[str]` 和可选 `cwd: str`。`argv` 是 JSON token 数组，不能是拼接后的命令；pipe、重定向、命令替换、
glob、环境变量展开、控制字符、URL 和 response-file 语法会在解析阶段拒绝。shell、解释器、提权工具和常见网络程序也不能注册为 executable。

宿主先用绝对 executable 和每个参数位置的完整 grammar 定义 capability：

```python
from sensitiveguard import CommandArgumentRule, CommandCapability

count_lines = CommandCapability(
    name="count_report_lines",
    executable="/usr/bin/wc",  # 部署时使用宿主验证过的绝对路径
    argument_rules=(
        CommandArgumentRule.fixed("mode", "-l"),
        CommandArgumentRule.read_path("report"),
    ),
    allow_cwd=False,
    network_allowed=False,      # True 会在构造阶段直接拒绝
    timeout_seconds=5,
    max_output_bytes=16_384,
    # executable_sha256="...64 位小写十六进制...",  # 生产环境建议固定
)
```

然后由宿主注入一个只接收 `AuthorizedCommand` 的 networkless sandbox executor：

```python
from sensitiveguard import AuthorizedCommand, CommandExecutionResult

class HostSandboxExecutor:
    def execute(self, command: AuthorizedCommand) -> CommandExecutionResult:
        # host_process_sandbox 是应用自己的隔离服务，不由 SensitiveGuard 提供。
        # 它必须接收 argv 序列；严禁 join、shell=True 或再次交给 shell 解析。
        result = host_process_sandbox.run_argv(
            argv=command.full_argv,
            cwd=str(command.cwd) if command.cwd is not None else None,
            network=False,
            close_fds=True,
            timeout=command.capability.timeout_seconds,
            max_output_bytes=command.capability.max_output_bytes,
        )
        return CommandExecutionResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            output_overflow=result.output_overflow,
            duration_ms=result.duration_ms,
        )

command_context = PrivacyContext(
    task="对授权报告执行固定的本地行数统计",
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
tools = command_runtime.build_tools(
    command_capabilities=(count_lines,),
    command_executor=HostSandboxExecutor(),
)
```

`command_capabilities` 和 `command_executor` 必须成对配置，少任何一项都不会暴露命令能力（工厂会抛出 `ValueError`）。executor 是宿主
可信计算基，必须使用 `AuthorizedCommand.full_argv`，执行前按 `executable_identity`/固定 digest 防 TOCTOU，关闭继承 fd，关闭网络，
执行在 OS/container sandbox 中，并执行 timeout 和 output byte limit。它的公开错误不能包含 argv、文件内容或进程原始输出。
生产环境还应通过 `command_fingerprint_key=` 注入独立 key；Audit 仅记录 keyed command fingerprint，不记录 raw argv。

命令 capability 还会检查 executable 不是 symlink、是普通可执行文件且不可被 group/world 写，路径参数必须通过 `allowed_roots`，
write path 默认不覆盖已有文件。只有 `text` 和 `path` 数据参数进入 Tool Input Guard；如果敏感内容需要被改写，该命令会直接拒绝而不是改变
参数语义后执行。stdout/stderr 只接受有界 UTF-8，移除 ANSI/控制字符，再经过 Tool Output Guard 才能进入 Memory。

模型调用形式也必须保持结构化，例如：

```json
{
  "capability": "count_report_lines",
  "argv": ["-l", "/data/reports/approved.txt"],
  "cwd": null
}
```

`"wc -l /data/reports/approved.txt"`、`["sh", "-c", "..."]`、`["-l", "*.txt"]` 和任何 raw shell 字符串都不受支持，
也不应由宿主自行“兼容”转换。

## 5. 敏感检测

默认 Runtime 的检测链完全离线：基础 `CompositeDetector([RegexDetector(), SecretDetector(), InjectionDetector()])` 再由
`NormalizationDetector` 和 `EncodedPayloadDetector` 补充检测 Unicode NFKC/零宽字符绕过，以及有界单层 URL percent、Base64、hex 编码绕过；
最外层 `CompositeDetector` 按严重性、置信度和 span 长度确定性消除重叠。Regex 使用 29 个规范化 PII 标签，Secret 额外覆盖密码、API key、
token、JWT、private key、云密钥和数据库密码，Injection 覆盖中英文间接提示注入模式。

```python
result = runtime.detector.detect("待检测文本", context)
if result.contains_sensitive_data:
    print(result.labels, result.counts())
    # to_dict() 不含 finding.value，可用于受控日志；不要自行读取/记录原始 span。
```

GLiNER 只在传入 `gliner_model`、`gliner_model_factory` 或 `gliner_model_path` 时加入检测链。`model_path` 使用
`local_files_only=True`；如果安装版本无法保证本地加载则拒绝。推荐由宿主离线预载并注入 `gliner_model=`。检测器返回无效 span、错误类型或不可用时，
Gateway 不会跳过该检测器继续外发。编码检测只承诺有界单层解码，不是任意递归解包或恶意文件解析器。

## 6. 无原文数据血缘

`LineageTracker` 已由 `SensitiveGuardRuntime.create()` 注入 Gateway。每次 `guard_text()`/`guard_payload()` 自动调用
`record_guard()`；Agent 安全审查还会在真实 Tool 调用前 `prepare_operation()`，成功后 `commit_operation()`。记录只包含按 run 隔离的
artifact/entity/leaf keyed HMAC、标签、taint、opaque tool/destination ref、父节点 ID 和 hash，不保存 payload、prompt、路径、URL、recipient
或敏感实体原文。

当后续输入与此前输出的完整 artifact、子树、scalar leaf 或实体 fingerprint 匹配时，父边自动传播。`PROMPT_INJECTION` taint 沿祖先传播；
带该 taint 的 lineage 不能触发外部/network/message effect。当前 Agent 安全审查还会保守地把同一 run 报告中存在任一 tainted artifact
视为本次外部调用已受 taint，而不是在证据不足时假设两者无关。每个 run 有独立 DAG 和 HMAC hash chain，禁止跨 run parent。

```python
report = runtime.lineage_tracker.report(context)
assert report.chain_valid
print(report.node_count, report.event_count, report.operation_states)

if report.nodes:
    parents = runtime.lineage_tracker.ancestors(report.nodes[-1].artifact_id, context)

# build_tools() 也默认提供 trace_data_lineage，其输出等价于 report.to_dict()。
```

非 Agent 的宿主 side effect 也应遵循两阶段状态：

```python
prepared = runtime.lineage_tracker.prepare_operation(
    guarded_input,
    context,
    operation_name="publish_report",
    tool_name="host_publish_report",
    destination="internal",
)

# 若宿主在调用 sink 前已经确定取消，可安全记录 ABORTED：
if operation_cancelled_before_sink:
    runtime.lineage_tracker.abort_operation(prepared.operation_id, context=context)
    raise RuntimeError("operation cancelled before execution")

try:
    output = host_publish(guarded_input)
except Exception:
    runtime.lineage_tracker.mark_indeterminate(prepared.operation_id, context=context)
    raise
else:
    runtime.lineage_tracker.commit_operation(prepared.operation_id, output, context=context)
```

只有能证明 side effect 未发生时才使用 `ABORTED`；超时、断连或 provider 状态不明必须用 `INDETERMINATE`。进程恢复时可调用
`recover_incomplete(context)` 将残留 `PREPARED` 保守标记为 `INDETERMINATE`。当前 tracker 是进程内组件；若业务需要跨进程留存，宿主应把
`to_dict()` 结果写入具备访问控制和完整性保护的存储，并安全保管 HMAC key，仍不得附带 raw payload。当前 API 不提供从序列化报告
重新装载 `LineageTracker` 的 loader；持久化、索引和跨进程校验需要由宿主单独实现。

## 7. 意图一致性

`IntentResolver` 对可信 `PrivacyContext.task + purpose` 只保留 keyed HMAC `goal_digest`，并生成绑定 `run_id`、version、TTL、operations、
capabilities、effects、fields、destinations 和 recipients 的 `IntentSpec`。Agent 在每次 `run(task)` 开始时只用创建 Agent 时注入的可信
`PrivacyContext` 建立 active intent；`run(task)` 的调用参数始终是不可信待处理数据，只能被检测和收窄，绝不能扩大 capability、effect 或
destination。可信 intent 解析失败时模型不会被调用。宿主不应直接用终端用户 prompt 构造授权上下文；应由受信业务层显式设置
`allowed_*`/`denied_*` 上限。

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
decision = runtime.intent_guard.validate_plan(intent, child)
assert decision.allowed
```

子计划只能缩小父 intent 的集合、缩短期限或增加 forbidden fields，不能增加字段、capability、recipient 或外部 route。动作还必须匹配 intent/plan
的 run、版本、签名和期限；同一 action request ID 只能消费一次。外部 destination 必须声明相应 `EXTERNAL`/`NETWORK`/`MESSAGE` effect，
`SEND`/`HANDOFF` 缺 destination、消息缺 recipient、side effect 欠报都会拒绝。任何祖先带 Prompt Injection taint 时，即使动作参数本身干净，
外部 effect 仍拒绝。

## 默认拒绝语义

SensitiveGuard 的“默认拒绝”不是单一规则，而是各边界共同成立：

| 边界 | 默认拒绝条件 |
| --- | --- |
| Policy | 敏感数据发往未列入 `known_external_destinations` 且无显式规则的外部目标，返回 `SG-EXTERNAL-DEFAULT-DENY`。 |
| Route | 未知/不可用/敏感度不匹配的 endpoint，无可用 endpoint，或本地 endpoint 未同时允许的 external fallback。 |
| Authorization | 未 allowlist 的 path、HTTP host、database table/field、recipient 或 Tool。 |
| Intent | 未授权 operation/capability/effect/field/destination/recipient，过期/伪造/版本不符/重放，或注入 taint 触发外部副作用。 |
| Review | manifest 未注册或实现/schema 变化，route 不匹配，lineage/audit/prepare 失败，permit 不匹配/过期/重放，或配额耗尽。 |
| Command | 没有宿主 executor、未知 capability、raw shell/不安全 token、路径越界、网络、敏感 argv、超时/溢出/非 UTF-8 输出。 |
| Gateway | 检测、策略、变换、ledger、approval、audit 或 lineage 失败；不会退回 raw 内容或直接调用 sink。 |

“拒绝”只保证不继续执行尚未发生的动作。对于调用后网络断连等无法判断外部副作用是否发生的情况，系统会阻止结果继续传播并记录
`INDETERMINATE`，但不能撤销外部系统可能已经完成的动作；宿主需要幂等 key、事务/outbox 和对账流程。

## 注入真实能力

真实客户端只保存在 Safe Tool 内部，不应同时暴露为普通 smolagents Tool：

```python
sent_prompts = []

def external_analysis_client(prompt: str) -> str:
    sent_prompts.append(prompt)
    return "分析完成"

tools = runtime.build_tools(
    external_llm_client=external_analysis_client,
    http_transport=trusted_http_transport,
    database_executor=read_only_database_executor,
    rag_retriever=scoped_retriever,
)
```

每个 callable 都采用依赖注入，便于在测试中断言 `BLOCK` 时真实 sink 的调用次数为零。
自定义 `SensitiveGuardTool` 默认仍会先经过统一 Tool Input Guard；只有可信宿主实现、且内部自行完成授权与输入保护的
Tool 才应显式设置 `handles_sensitive_input = True`。继承 marker 本身不是沙箱或安全证明。

## 创建 smolagents Agent

```python
from smolagents import LiteLLMModel

planner = LiteLLMModel(
    model_id="ollama_chat/qwen2.5:3b",
    api_base="http://127.0.0.1:11435",
    api_key="ollama",
)

agent = runtime.create_agent(
    planner,
    tools=tools,
    model_destination="local",  # 外部 Planner 应写 external_llm
    max_steps=12,
)

result = agent.run("扫描授权目录，生成脱敏副本并输出审计摘要")
```

此 Agent 明确拒绝 `CodeAgent` 式任意代码能力、base tools、未守卫 managed agents 和模型 token streaming。
对外的 `run(stream=True)` 仍可使用，但只产生已经清洗的事件。

## 审批高敏必要披露

高敏数据确有必要且跨越信任边界时，策略返回 `REQUIRE_APPROVAL`。默认 `ApprovalStore` 自动创建待审批项：

```python
pending = runtime.approval_store.pending(context.run_id)
request = pending[0]
runtime.approval_store.approve(request.request_id, approver="privacy-officer")

# 使用完全相同的内容、run 和 destination 重试一次
```

审批通过后只能消费一次，并绑定内容的 keyed HMAC、run、目标和策略动作。更改内容、重放、超时或更换目标都会重新要求审批；
批准的原始披露仍按 raw exposure 计入 Disclosure Ledger。

## 文件、RAG、Memory 与 MCP

- `sanitize_file` 只创建新文件，拒绝覆盖源文件或已有输出，写入后再次验证原值已经消失。
- `safe_query_database` 不接受 raw SQL 或 `SELECT *`，只接受结构化 table、fields 和 filters。
- `safe_retrieve_rag` 要求授权 scope，可要求每个 chunk 带 scope metadata，并在 Memory 前扫描注入和敏感内容。
- `MemoryGuard` 清洗 model output、tool arguments、observation、error 和 provider raw 副本。
- `HandoffGuard` 仅传递 worker 的允许字段及显式 artifact capability。
- `MCPGateway` 对未知 server 默认拒绝，并依次执行 trust、严格 schema、input guard、调用、output schema 和 output guard。

HTTP transport 属于可信计算基。生产实现必须禁用自动 redirect（或逐跳重新执行 allowlist/私网校验），并把连接固定到
授权阶段验证过的地址，同时保留正确的 Host/SNI；仅校验 URL 字符串不能彻底消除 DNS rebinding。文件系统同样应配合只读
挂载、最小 OS 权限和不可由低权限主体替换的授权根目录，运行时的 `resolve`/`O_NOFOLLOW` 不是操作系统隔离的替代品。

## 验证

离线运行三个验收场景：

```bash
PYTHONPATH=src python examples/sensitiveguard/offline_demo.py
```

运行安全测试：

```bash
PYTHONPATH=src pytest tests/sensitiveguard
```

测试应同时检查真实 sink、Agent Memory、stream event、异常、Audit 和最终答案中都不存在原始 canary。

## 能力边界

Regex 不是 GLiNER 的替代品，GLiNER 也不是授权策略。真实部署还需要根据数据集校准阈值和风险权重，配置可靠的审计存储、
密钥管理、审批身份系统、模型超时和数据保留策略，并针对业务敏感文档增加专用分类器。SensitiveGuard 在检测器或策略失败时默认
拒绝外发，但不能替代操作系统权限、网络 egress 控制、数据库权限或组织治理。
