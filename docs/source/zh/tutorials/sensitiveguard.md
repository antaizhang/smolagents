# 使用 SensitiveGuard 构建敏感数据安全 Agent

SensitiveGuard 是一个独立于模型的隐私运行时。它把 smolagents 的 `ToolCallingAgent` 用作规划与工具选择层，
把检测、最小化、确定性策略、变换、授权、隐私预算和审计放在模型无法绕过的运行时边界中。

它保护四条通道：

1. 任务和数据获取进入模型之前；
2. Tool 参数进入真实系统之前；
3. Tool observation 写入 Agent Memory 之前；
4. 普通或达到步数上限的最终答案返回之前。

## 安装

核心运行时不需要下载模型，默认使用 Regex、Secret 和 Prompt Injection 检测器。GLiNER 是可选依赖：

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
