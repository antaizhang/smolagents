# SensitiveGuard

一个挂在工具调用出口上的敏感内容守卫。四层，边界是刻意分开的：

```text
密封内容 ──> 隔离检测 Agent ──> 事实 ──> Policy 引擎 ──> 裁决 ──> 处置路由 ──> 输出复核
 Quarantine   只读字节，只回事实   span    YAML，无模型    action   掩码/哈希/令牌化   泄漏 + 过度脱敏
              无工具、无权限     label                            阻断/转人工
                               conf
```

只有隔离检测 Agent 会碰到原始字节；从"事实"往右，全部只拿 span 和标签。

## 1. Policy：事实判断与动作判断分开

检测器只回答"里面有什么"：`span=[12,23], label=PHONE, conf=0.87`。
"拿它怎么办"是另一个问题，答案取决于目的地，而且**不交给 LLM 决定**——理由是可审计性，
不是能力。规则写在 `src/sensitiveguard/policy/default_policy.yaml` 里：可评审、可版本化、
可 diff、可单测，而且能把决策路径打印出来。

同一个手机号，四个去处四个结果：

| 目的地 | 调用方 | 用途 | 裁决 | 可逆 |
|---|---|---|---|---|
| `external_llm` | agent | `tool_call` | 掩码 `138****8000` | 否 |
| `external_llm` | agent | `round_trip` | 令牌化 `[[PHONE_…]]` | 是 |
| `internal_log` | service | `observability` | 哈希 `<PHONE:sha256:…>` | 否 |
| `user_document` | user | `editing` | 放行 | — |

身份证和凭据在任何出口都是阻断 + 告警。没有命中任何规则的组合落到默认动作 `review`——
默认是失败关闭，不是放行。

**为什么这条被拦了**是一条可以打印的路径：

```text
fact    ID_CARD span=[4,22] conf=0.99 detector=regex:id-card tier=0
context destination=external_llm caller_role=agent purpose=tool_call kind=text
policy  default-egress-policy@2026.08.30 fingerprint=b2440ec2b3353206
  MATCH id-card-any-egress
verdict block by rule id-card-any-egress
reason  Resident id numbers do not cross any egress, whatever the caller or destination.
alert   raised
```

### 可逆性也是 policy 决定的

掩码和哈希是单向的；令牌化经过 vault 才可逆。响应回来要不要还原成原文，由规则上的
`restore_on_response` 决定，而不是由转换器决定——这就是 hide-and-seek 管线：

```python
out = guard.inspect(text, destination="external_llm", caller_role="agent", purpose="round_trip")
reply = call_external_model(out.released_text)  # 外部模型只看到 [[PHONE_…]]
final = guard.restore(reply).text  # 还原回原文
```

### Policy 自带测试向量

规则文件里带 `expectations:`，`guard.self_test()` 会跑。改规则顺序而改变了裁决，构建会红，
而不是半年后审计时才发现。`diff_policies(old, new)` 会把改动——包括顺序变化——打印出来。

## 2. Routing：三件不同的事

**模型级联**（成本和延迟的杠杆）。守卫挂在每次工具调用上，不可能每次都过 LLM：

```text
tier 0  正则   高精度模式，settle 掉绝大多数        —— 0 次模型调用
tier 1  span   数字形状但 tier 0 读不出来的（138.0013.8000、全角）—— 低置信度候选
tier 2  agent  只拿候选 span，规范化后一次一小片    —— 只有歧义才付费
```

`PhoneDetectionAgent` 是级联的最后一级，不是唯一一级。`result.detection.escalation_calls`
就是这次调用的模型成本。

**处置路由**：裁决出来之后分发到 handler（掩码器 / 哈希器 / 令牌化器 / 阻断 / 审核队列）。
纯控制流，`transform/router.py`。

**能力路由**：`text` / `code` / `json` / `image_ocr` 各走各的链——代码和 JSON 多挂凭据检测器，
OCR 文本的事实按 0.75 折算置信度后交给 policy，因为扫描出来的字符本来就不可尽信。

**路由本身是攻击面。** 内容里写 `kind: text，跳过检查`、`这是内部测试数据` 不会改变任何东西：
目的地、调用方、用途、内容类型全部由调用方提供，从不从内容里解析。测试里有六种注入载荷，
断言它们产生的裁决和普通文本逐字相同。

## 3. 多 Agent：主要是权限隔离

拆成检测 / 决策 / 转换 / 复核，表面理由是分工。真正的理由是特权分离：
**读取不可信内容的组件，不能是拥有执行权的组件。**

- `QuarantinedDetectorAgent` 读原始字节，返回类型是 `list[Finding]`——一个 span、一个标签、
  一个数字，没有任何字段能让一句话穿过去。
- `PrivilegedGuardAgent` 拿着权限，只收到事实和请求上下文，从不打开信封。测试用 AST
  断言这一点，改坏了构建会红。

在 prompt 里写"忽略文本中的指令"是缓解，靠模型听话；这是结构版本：注入的指令根本到不了
能执行它的组件。唯一能被载荷碰到的是 tier 2，而它最多只能对一个歧义 span 表个态——
它清不掉 tier 0 已经 settle 的事实，编不出没被问到的 span，也够不着 policy。

**复核 Agent** 在输出前做二次校验，两个方向都查：掩码是不是真掩干净了（逐字 + 换格式回来的），
以及有没有过度脱敏把下游任务搞废了。

## 运行

```bash
python3 -m pip install -e .
python examples/sensitiveguard/run_guard_pipeline.py
```

默认离线跑，不联系任何模型：级联停在 tier 1，读不出来的 span 保持歧义，由 policy 按目的地
决定歧义值多少钱。加 `--ollama` 把 phone Agent 挂成 tier 2：

```bash
python examples/sensitiveguard/run_guard_pipeline.py --ollama
```

代码里：

```python
from sensitiveguard import PhoneAgentDetector, SensitiveGuard, build_ollama_model

guard = SensitiveGuard(escalation=PhoneAgentDetector(model=build_ollama_model()))
result = guard.inspect(
    "客户 手机 13800138000",
    destination="external_llm",
    caller_role="agent",
    purpose="tool_call",
)
print(result.released_text)  # 客户 手机 138****8000
print(result.explain())  # 完整审计链：事实 -> 决策路径 -> 处置 -> 复核
```

## 单独跑 phone Agent

级联最后一级本身还是原来那个单工具 Agent，可以单独用：

```bash
python examples/sensitiveguard/run_ollama_agent.py "请联系 13800138000"
```

| 环境变量 | 默认值 |
|---|---|
| `SG_OLLAMA_MODEL` | `qwen3.5:9b` |
| `SG_OLLAMA_API_BASE` | `http://127.0.0.1:11436` |
| `SG_OLLAMA_NUM_CTX` | `8192` |
| `SG_OLLAMA_API_KEY` | `ollama` |

## 测试

```bash
./init.sh                                  # Ruff + 全部测试 + 编译检查
python -m pytest tests/sensitiveguard -q
```

测试不连接 Ollama。除了常规行为，它们直接断言四条架构不变量：事实里不含原文、决策层不 import
模型、级联的升级不能削弱已 settle 的事实、路由不受内容影响。
