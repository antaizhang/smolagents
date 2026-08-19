# 敏感数据识别：机制拆解 + 可运行的单元测试

这个目录专讲一件事：**一段文本进来，SensitiveGuard 是怎么把里面的敏感数据识别出来的。**
不涉及策略、脱敏、外发拦截——只看"识别"这一步的内部过程。

两个文件，配套使用：

| 文件 | 作用 |
| --- | --- |
| `detection_walkthrough.py` | 把检测链**逐层跑一遍并打印**，你能看到每一层各自贡献了什么 |
| `test_detection_walkthrough.py` | 把每个结论写成**可运行、可阅读的断言**，测试名就是知识点 |

## 怎么跑

```bash
# 装好包（仓库根目录，任选其一）
pip install -e .
#   或复用已有的 .venv-demo： .venv-demo/bin/python ...

# 1) 看逐层过程（会打印一大段带偏移、级别、来源的表格）
python examples/sensitiveguard/detection/detection_walkthrough.py

# 2) 跑单元测试（26 个，全部离线，1 秒内）
pytest examples/sensitiveguard/detection/test_detection_walkthrough.py -v
```

---

## 一张图看懂整条链

```text
                          原始文本  content: str
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌──────────────┐      ┌──────────────────┐    ┌────────────────────┐
 │ 第1层 词法    │      │ 第2层 归一化      │    │ 第3层 编码解码       │
 │ 直接在原文    │      │ NFKC + 去零宽     │    │ 框出 Base64/hex/URL% │
 │ 上跑正则      │      │ 得到"干净文本"     │    │ 解一层 -> 再跑词法    │
 │              │      │ 再跑词法          │    │                    │
 │ Regex        │      │ 命中后把偏移       │    │ 命中后产出一个        │
 │ Secret       │      │ 映射回原文         │    │ 覆盖整段密文的 Finding │
 │ Injection    │      │                  │    │                    │
 └──────┬───────┘      └────────┬─────────┘    └──────────┬─────────┘
        │  Finding[]            │ Finding[]               │ Finding[]
        └───────────────────────┼─────────────────────────┘
                                ▼
                  ┌────────────────────────────┐
                  │  CompositeDetector 汇总      │
                  │  deduplicate_findings():     │
                  │  按级别>分数>跨度>顺序排序，   │
                  │  贪心去掉重叠命中             │
                  └──────────────┬─────────────┘
                                 ▼
                       DetectionResult
                   .findings / .labels / .counts()
```

上面三层就是 `SensitiveGuardRuntime.create()` 在 `src/sensitiveguard/factory.py` 里组装的东西
（若传入本地 GLiNER 模型，会再在最前面插一个 `GLiNERDetector`，默认不加载、不联网）。
`detection_walkthrough.py` 里的 `build_detector()` 手工复刻了这条链，脚本结尾会断言它和真实
`runtime.detector` 结论一致，所以下面讲的都能对上真实实现。

---

## 每一层到底做了什么

### 第 1 层 · 词法检测（`RegexDetector` / `SecretDetector` / `InjectionDetector`）

直接在原文上跑正则，命中即产出 `Finding`。三类正则各司其职：

- **`RegexDetector`**：29 类 PII 格式。分两种锚定方式：
  - *自锚定*：身份证、手机号、邮箱、IP 这些格式够独特，靠 `(?<!\d)(?!\d)` 之类的边界
    加内建校验（身份证连出生年月日段都在正则里校验）就能命中，不需要上下文词。
  - *前缀锚定*：姓名、地址、银行卡这些光看内容会误报，所以要求前面出现 `姓名` / `address` /
    `银行卡` 这类前缀词才命中——这是**降低误报**的关键设计。
- **`SecretDetector`**：AK/SK（`AKIA…`）、JWT、私钥块、数据库连接串口令等，一律 `CRITICAL`。
- **`InjectionDetector`**：中英文提示注入语句，命中打 `PROMPT_INJECTION` 标签。

每个 `Finding` 都带：`label`、**精确的 `[start:end]` 偏移**（可直接切片原文）、`score`、
`severity`、以及是哪个 `detector` 给的。

对应测试：`test_idcard_is_self_anchored_*`、`test_name_and_address_need_a_context_prefix`、
`test_secret_detector_*`、`test_injection_detector_*`、`test_a_finding_carries_exact_offsets_*`。

### 第 2 层 · Unicode 归一化（`NormalizationDetector`）

对抗『看起来是数字但不是 ASCII 数字』的规避，比如全角 `４４０…` 或手机号中间插零宽字符。

做法：**逐字符**做 NFKC 归一化、丢弃零宽字符，拼出一份"干净文本"，同时维护一张
`source_indexes` 映射表（干净文本的第 i 个字符来自原文第几位）。在干净文本上跑第 1 层，
命中后用映射表把偏移**换算回原文**。

两个重要细节：
- 报告里的 `value` 仍是**原文那一段带变形的文本**（连零宽字符一起），所以后续脱敏能整段删掉，不留残渣；
- 若归一化后和原文一模一样，本层直接返回空——避免和第 1 层重复上报同一处。

对应测试：`test_fullwidth_digits_are_caught_after_nfkc`、
`test_zero_width_character_inside_a_number_is_defeated`、
`test_normalized_finding_maps_back_to_original_span_*`、
`test_normalization_layer_stays_silent_when_text_is_already_canonical`。

### 第 3 层 · 单层编码解码（`EncodedPayloadDetector`）

对抗『把敏感值编码一下藏起来』，覆盖 Base64、十六进制、URL 百分号三种。

做法：正则先框出候选 token → 只做**单层**解码（防解码炸弹）→ 解出的明文再喂回第 1 层。
一旦解码后有敏感命中，就产出**一个覆盖整个编码 token** 的 `Finding`（`value` 是原始密文，
label/级别取解码后最严重的那个）。这样脱敏时会把整段密文一起抹掉，而不是只删中间几个字符
破坏编码结构。`detector` 名字形如 `encoded:base64:regex`，方便追溯。

对应测试：`test_base64_wrapped_idcard_is_decoded_and_flagged`、
`test_encoded_finding_covers_the_whole_token_*`、
`test_all_three_single_layer_encodings_are_handled`、`test_decoding_is_single_layer_only`。

### 汇总层 · 合并去重（`CompositeDetector` + `deduplicate_findings`）

外层 `CompositeDetector` 把三层的 `Finding` 全收上来，交给 `deduplicate_findings()` 裁决。
排序键（越靠前优先级越高）：

1. 级别更高（`CRITICAL > HIGH > MEDIUM > LOW`）
2. 分数更高
3. 覆盖跨度更长
4. 原始检测器顺序更靠前

然后**贪心**保留互不重叠的命中：新命中只要和已选中的任何一个在字符区间上相交就丢弃。
最后按 `start` 偏移排序输出，方便下游脱敏顺序处理。

对应测试：`test_overlapping_findings_keep_the_more_severe_one`、
`test_non_overlapping_findings_are_all_kept_and_sorted_by_start`、
`test_equal_severity_prefers_higher_score_then_longer_span`。

---

## 输出契约：`DetectionResult`

```python
result = detector.detect(text)  # 或 runtime.detector.detect(text, context)
result.contains_sensitive_data  # bool
result.labels  # 去重且排序后的标签元组
result.counts()  # {标签: 次数}
result.to_dict()  # 对外序列化——只含 label/偏移/分数/级别，**绝不含原始命中值**
```

`Finding.value`（原始命中文本）被刻意排除在 `repr` 和 `to_dict()` 之外，只在进程内部供脱敏层
核对区间用。对应测试：`test_to_dict_never_leaks_the_raw_value`。

---

## 级别是怎么定的

由 `src/sensitiveguard/detector/labels.py` 的 `severity_for_label()` 决定，是**按标签查表**的固定映射：

| 级别 | 覆盖标签（节选） |
| --- | --- |
| `CRITICAL` | 身份证、银行卡、护照、各类证件号、口令、所有密钥类、`PROMPT_INJECTION` |
| `HIGH` | 手机、邮箱、地址、传真、座机、IMEI/IMSI、车架号、车牌 |
| `MEDIUM` | 姓名、IPv4/IPv6、MAC |

正则规则也可以在 `RegexPattern(..., severity=...)` 里显式覆盖默认级别（密钥类就是这么强制为
`CRITICAL` 的）。

---

## 想扩展？

加一个新的 PII 格式，只需往 `RegexDetector` 传自定义 `RegexPattern`：

```python
from sensitiveguard.detector import RegexDetector, CompositeDetector
from sensitiveguard.detector.regex_detector import RegexPattern
from sensitiveguard.models import Severity

my_rules = RegexDetector((RegexPattern("EMPLOYEE_ID", r"(?<!\w)(?P<value>EMP-\d{6})(?!\w)", 0.97, Severity.HIGH),))
detector = CompositeDetector([my_rules])
print(detector.detect("工号 EMP-004521").labels)  # ('EMPLOYEE_ID',)
```

`group="value"` 表示只把命名组 `value` 当作敏感值上报（前缀/上下文不算），这正是内建规则的写法。

---

## 相关源码

- 检测器基类与协议：`src/sensitiveguard/detector/base.py`
- 词法正则库：`src/sensitiveguard/detector/regex_detector.py`、`secret_detector.py`、`injection_detector.py`
- 归一化 / 编码层：`src/sensitiveguard/detector/normalization_detector.py`、`encoded_detector.py`
- 合并去重：`src/sensitiveguard/detector/composite.py`
- 级别映射：`src/sensitiveguard/detector/labels.py`
- 链的组装：`src/sensitiveguard/factory.py`（`SensitiveGuardRuntime.create`）
- 仓库自带的检测器测试：`tests/sensitiveguard/test_detection_policy.py`
