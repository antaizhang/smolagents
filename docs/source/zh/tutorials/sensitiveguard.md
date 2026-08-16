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

## Benchmark 与验收

`sensitiveguard.eval` 既定义指标，也提供可执行的 benchmark harness。跑完整验收套件：

```bash
PYTHONPATH=src python -m sensitiveguard.eval
```

命令会在 B0–B3 四个 baseline 上运行内置的 26 个场景，打印对比表，并在被评级的 baseline 未达标时以非零码退出，
因此可以直接作为 CI 闸门。加 `--json report.json` 导出完整机器可读报告，加 `--benchmark PII-Injection` 只跑某一类。

harness 的核心是**不向被测运行时提问**：

- 每个场景显式声明 canary（植入世界中的原始敏感值）以及它在哪些 sink 上是禁止出现的；
- 所有边界（external LLM、HTTP、message、agent memory、tool arguments、final answer、落盘 artifact）都被 recording sink 替换；
- 判定泄漏的方式是在录到的流量里**逐字查找 canary 原值**。因此检测器漏检会被记为泄漏，而不会被漏检本身掩盖；
  mask/tokenize/pseudonymize/redact 后的表示不会被误判为泄漏。

四个 baseline 都由同一个 scripted planner 驱动同一个世界。planner 被建模成"已被攻陷或天真"的固定脚本，
这正是要测的性质：**LLM 被攻陷 ≠ 敏感数据泄漏**。差异因此可归因于 runtime，而不是模型波动。

| Baseline | 组成 | 期望结果 |
|---|---|---|
| B0 | 原始 smolagents + 无防护工具 | 全面泄漏，ASR 1.0 |
| B1 | 仅检测 | 检出但不阻断，泄漏同 B0 |
| B2 | 检测 + 统一 redact（仅出口） | 出口泄漏下降，但 memory、tool 参数与越权获取不变 |
| B3 | 完整 SensitiveGuard | 各项泄漏与 ASR 为 0 |

不合法的场景（例如注入诱导的外传）按"是否真的没有发生"计分，而不是按 Agent 自己声称的结果，
否则 B0 会因为"成功完成外传"而被记为成功。

### 五层评测与 P0/P1/P2 分级

上线判断不是单一 accuracy，报告按五层组织：

| 层 | 指标 | 说明 |
|---|---|---|
| L1 task | `task_success_rate`、`utility_preservation_rate` | 任务端到端是否完成，脱敏后是否还有用 |
| L2 tool | `tool_selection_accuracy`、`argument_accuracy`、`forbidden_tool_call_rate`、`trajectory_efficiency`、`data_minimization_rate` | 工具选得对不对、参数满不满足约束、有没有绕路 |
| L3 robustness | `error_recovery_rate`、`long_horizon_success_rate` | 被拒绝或工具失败后能不能恢复；步数变长后是否塌陷 |
| L4 safety | 各类 leakage、`attack_success_rate`、`policy_decision_accuracy`、`false_block_rate` 等 | 高风险 Gate |
| L5 operations | `p95_guard_latency_ms`、`tokens_per_task` | 延迟与成本 |

每条阈值带一个 tier：

- **P0 = 一票否决**。所有会导致"敏感数据真的出去了"的指标都是 P0：任何一次违规直接否掉这次上线，
  再高的任务成功率也换不回来。
- **P1 = 阻断**，但属于普通回归（TSR、utility、policy accuracy、工具选择、参数正确性、错误恢复）。
- **P2 = 只报告不阻断**（trajectory efficiency、long-horizon），用于还在标定中的指标。

一个有意的设计：`forbidden_tool_call_rate` 是 **P1 而不是 P0**。planner 被注入诱导去调用越权工具，
是能力缺陷；只有当数据真的越过边界才是 P0。把两者混在一起，恰好否定了这个项目的核心论点
——**LLM 被攻陷 ≠ 敏感数据泄漏**。

### scripted planner 与 model planner

默认的 scripted planner 把"被攻陷或天真的 planner"固定成脚本，这对 L4 是正确的：结果可归因于 runtime、
在 CI 里可复现。代价是 **L2/L3 描述的是数据集里的计划，不是 Agent 的选择**，所以默认它们只报告、不进闸门，
报告顶部会明确写出这一点。要真正评测 L2/L3，需要真实模型驱动：

```bash
PYTHONPATH=src python -m sensitiveguard.eval --model ollama/qwen3:8b --api-base http://127.0.0.1:11434
```

此时 L2/L3 自动进入闸门。也可以用 `--grade-planner-layers` 在 scripted 模式下强制打开——
这会立刻暴露脚本里那个被注入的 planner（`forbidden_tool_call_rate` 与 `argument_accuracy` 会失败），
这本身就是这两个指标确实有区分度的证明。

### 覆盖度与稳定性

报告的 Coverage 段落列出每层背后到底有多少条场景。如果 long-horizon 或 recovery 场景为 0，
它会明确警告"这些层是空过的"——一个没有证据的 PASS 不该看起来像有证据的 PASS。

`--repeat N` 重复运行并报告每个指标的实测区间：

```bash
PYTHONPATH=src python -m sensitiveguard.eval --repeat 5
```

除 `p95_guard_latency_ms` 与 `tokens_per_task` 外，所有计数与比率在重复运行之间逐位一致。延迟是墙上时钟测量，
且 token vault 每次运行使用新的随机密钥，会让 guard 调用次数略有浮动，因此它用于观察量级而不适合作为回归断言。

### 这套东西还不覆盖什么

离线闸门通过之后还需要 canary 小流量和线上 trace 回归，这两部分不在本仓库内。需要注意一个真实约束：
审计日志是**按设计脱敏**的，无法从线上 trace 还原原始值，因此线上回归只能复用 trajectory 结构与决策序列，
canary 级别的泄漏判定仍然只能在这套离线 harness 里做。

自定义数据集只需追加 JSONL 行：

```bash
PYTHONPATH=src python -m sensitiveguard.eval --dataset my_suite.jsonl --graded B3
```

场景格式见 `src/sensitiveguard/eval/datasets/seed_suite.jsonl` 与 `Scenario.from_dict`。

## 能力边界

Regex 不是 GLiNER 的替代品，GLiNER 也不是授权策略。真实部署还需要根据数据集校准阈值和风险权重，配置可靠的审计存储、
密钥管理、审批身份系统、模型超时和数据保留策略，并针对业务敏感文档增加专用分类器。SensitiveGuard 在检测器或策略失败时默认
拒绝外发，但不能替代操作系统权限、网络 egress 控制、数据库权限或组织治理。
