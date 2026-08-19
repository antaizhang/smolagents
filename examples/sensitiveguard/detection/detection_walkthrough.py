"""敏感数据识别：把整条检测流水线一层层拆开给你看。

这个脚本不是『调用一个函数拿结果』，而是把 SensitiveGuard 内部**每一层**都单独跑一遍，
打印它各自贡献了什么，最后再展示合并（去重）后的结果。读完你就清楚：

    一段文本进来，到底经过了哪几步，每一步做了什么，最终的标签是怎么来的。

直接运行看逐层过程：

    python examples/sensitiveguard/detection/detection_walkthrough.py

配套的单元测试（把下面每个结论都变成可断言的用例）：

    pytest examples/sensitiveguard/detection/test_detection_walkthrough.py -v

全程离线：不联网、不加载模型。用到的就是标准库正则 + Unicode 归一化 + 单层解码。
"""

from __future__ import annotations

import base64
from collections.abc import Iterable

from sensitiveguard.detector import (
    CompositeDetector,
    EncodedPayloadDetector,
    InjectionDetector,
    NormalizationDetector,
    RegexDetector,
    SecretDetector,
)
from sensitiveguard.detector.composite import deduplicate_findings
from sensitiveguard.models import DetectionResult, Finding, Severity


# ---------------------------------------------------------------------------
# 1. 复刻 runtime 内部那条检测链
#
#    这正是 SensitiveGuardRuntime.create() 在 factory.py 里组装的东西。我们在这里
#    手动搭一遍，是为了能把中间每一层单独拿出来观察。build_detector() 返回的对象和
#    runtime.detector 行为一致（脚本末尾会断言二者标签相同）。
# ---------------------------------------------------------------------------


def build_lexical_detector() -> CompositeDetector:
    """第一层：三个纯词法检测器合在一起，直接在原文上跑正则。

    - RegexDetector    : 29 类 PII 格式（身份证 / 手机 / 银行卡 / 邮箱 / IP …）
    - SecretDetector   : 凭据密钥（AK/SK、JWT、私钥、数据库口令），全部 CRITICAL
    - InjectionDetector: 中英文提示注入语句 -> PROMPT_INJECTION
    """
    return CompositeDetector([RegexDetector(), SecretDetector(), InjectionDetector()])


def build_detector() -> CompositeDetector:
    """完整检测链 = 词法层 + 归一化层 + 编码层，外面再套一层 Composite 做统一去重。"""
    lexical = build_lexical_detector()
    return CompositeDetector(
        [
            lexical,  # 第 1 层：原文上的词法匹配
            NormalizationDetector(lexical),  # 第 2 层：抗 Unicode 变形（全角 / 零宽）
            EncodedPayloadDetector(lexical),  # 第 3 层：抗单层编码（Base64 / hex / URL%）
        ]
    )


# ---------------------------------------------------------------------------
# 2. 打印辅助
# ---------------------------------------------------------------------------


def _fmt_findings(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    if not findings:
        return "      （无）"
    lines = []
    for f in findings:
        lines.append(
            f"      {f.label:<12} 位置[{f.start:>2}:{f.end:<2}] "
            f"分数={f.score:<5} 级别={f.severity.value:<8} 来源={f.detector:<22} 命中={f.value!r}"
        )
    return "\n".join(lines)


def _rule(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# ---------------------------------------------------------------------------
# 3. 逐层演示
# ---------------------------------------------------------------------------


def demo_layer_1_lexical() -> None:
    _rule("第 1 层 · 词法检测（RegexDetector / SecretDetector / InjectionDetector）")
    lexical = build_lexical_detector()
    text = "客户姓名 张三，手机 13800138000，身份证 440101199001011234，AKIA1234567890ABCDEF"
    print(f"输入：{text}\n")
    print("命中（已在本层内部按重叠去重）：")
    print(_fmt_findings(lexical.detect(text).findings))
    print(
        """
要点：
  - IDCARD/MOBILE 是『自锚定』正则：靠前后 (?<!\\d)(?!\\d) 边界 + 身份证的日期段校验，无需前缀；
  - 姓名/地址等靠『前缀锚定』：必须出现 姓名 / address 这类上下文词才命中，降低误报；
  - AKIA... 由 SecretDetector 命中，级别 CRITICAL；
  - 每个 Finding 记录 label / 精确 [start:end] 偏移 / 分数 / 级别 / 是哪个检测器给的。"""
    )


def demo_layer_2_normalization() -> None:
    _rule("第 2 层 · Unicode 归一化（NormalizationDetector）")
    normalized = NormalizationDetector(build_lexical_detector())

    fullwidth = "身份证 ４４０１０１１９９００１０１１２３４"  # 全角数字
    zero_width = "手机 1380013​8000"  # 手机号中间插了一个零宽字符

    for tag, text in [("全角数字身份证", fullwidth), ("零宽字符断开手机号", zero_width)]:
        print(f"\n输入（{tag}）：{text!r}")
        print("  直接词法检测：")
        print(_fmt_findings(build_lexical_detector().detect(text).findings))
        print("  归一化层：")
        print(_fmt_findings(normalized.detect(text).findings))
    print(
        """
要点：
  - 归一化层先按字符做 NFKC 归一化并丢弃零宽字符，得到一份『干净文本』；
  - 它维护一张『归一化位置 -> 原文位置』的映射表 source_indexes，命中后把偏移映射回原文；
  - 所以报告里的 value 仍是**原始那段带变形的文本**（连零宽字符一起），脱敏时能整段删掉；
  - detector 名字带 normalized: 前缀，分数上限压到 0.98（比原文直接命中略降一档）；
  - 若归一化后与原文完全相同，本层直接返回空，避免和第 1 层重复报同一处。"""
    )


def demo_layer_3_encoded() -> None:
    _rule("第 3 层 · 单层编码解码（EncodedPayloadDetector）")
    encoded = EncodedPayloadDetector(build_lexical_detector())

    b64 = base64.b64encode("身份证 440101199001011234".encode()).decode()
    hex_token = "身份证 440101199001011234".encode().hex()
    percent = "".join(f"%{ord(c):02X}" for c in "440101199001011234")

    samples = [
        ("Base64", f"note={b64}"),
        ("Hex", f"blob {hex_token}"),
        ("URL 百分号编码", f"q={percent}"),
    ]
    for tag, text in samples:
        print(f"\n输入（{tag}）：{text}")
        print("  直接词法检测：")
        print(_fmt_findings(build_lexical_detector().detect(text).findings))
        print("  编码层：")
        print(_fmt_findings(encoded.detect(text).findings))
    print(
        """
要点：
  - 用正则先框出候选 token（连续的 Base64 / 十六进制 / 百分号序列）；
  - 对每个 token 只做**单层**解码（防解码炸弹），解出来的明文再喂回词法检测器；
  - 一旦解码后文本里有敏感命中，就产出**一个覆盖整个编码 token** 的 Finding；
    这样脱敏时会把整段密文抹掉，而不是只删中间几个字符破坏编码；
  - value 是原始编码串，label/级别取解码后最严重的那个命中，detector 名如 encoded:base64:regex。"""
    )


def demo_merge_and_dedup() -> None:
    _rule("汇总层 · 合并去重（CompositeDetector + deduplicate_findings）")
    print(
        """外层 CompositeDetector 把三层的 Finding 全部收集起来，再交给 deduplicate_findings() 统一裁决。
裁决规则（排序键，越靠前优先级越高）：
  1) 级别更高（CRITICAL > HIGH > MEDIUM > LOW）
  2) 分数更高
  3) 覆盖的字符跨度更长
  4) 原始检测器顺序更靠前
然后**贪心**地保留互不重叠的命中：只要新命中与已选中的任何一个在字符区间上相交，就丢弃。
最终再按 start 偏移排序输出，方便下游脱敏顺序处理。"""
    )

    # 手工构造一组『重叠』的原始命中，直观展示裁决过程。
    raw = [
        Finding("NAME", 0, 6, 0.88, Severity.MEDIUM, "regex", value="张三丰abc"),
        Finding("IDCARD", 3, 9, 0.99, Severity.CRITICAL, "regex", value="345678"),
        Finding("MOBILE", 20, 31, 0.99, Severity.HIGH, "regex", value="13800138000"),
    ]
    print("\n裁决前（3 条，其中前两条区间 [0:6] 与 [3:9] 相交）：")
    print(_fmt_findings(raw))
    print("\n裁决后：")
    print(_fmt_findings(deduplicate_findings(raw)))
    print(
        "\n结论：[0:6] 的 NAME(medium) 与 [3:9] 的 IDCARD(critical) 相交，"
        "IDCARD 级别更高被保留，NAME 被丢弃；不相交的 MOBILE 原样保留。"
    )


def demo_full_pipeline() -> None:
    _rule("端到端 · 一段混合文本走完整条链")
    detector = build_detector()
    text = (
        "客户张三，手机1380013​8000，"  # 零宽变形手机号 -> 第 2 层
        "身份证440101199001011234，"  # 明文身份证 -> 第 1 层
        "备份=" + base64.b64encode("bank account 6222020200001234567".encode()).decode()  # Base64 银行卡 -> 第 3 层
    )
    result = detector.detect(text)
    print(f"输入：{text}\n")
    print("最终 DetectionResult.findings：")
    print(_fmt_findings(result.findings))
    print(f"\n  contains_sensitive_data = {result.contains_sensitive_data}")
    print(f"  labels  = {result.labels}")
    print(f"  counts  = {result.counts()}")
    print("\n  to_dict()（对外序列化，注意：**不含** value 原文，只有标签和偏移）：")
    for item in result.to_dict()["findings"]:
        print(f"    {item}")


def assert_matches_runtime() -> None:
    """证明：这里手搭的链，和真实 runtime 用的检测器，结论一致。"""
    from sensitiveguard import PrivacyContext, SensitiveGuardRuntime

    context = PrivacyContext(task="detection walkthrough", purpose="teaching", allowed_scope=("text",))
    runtime = SensitiveGuardRuntime.create(context)
    manual = build_detector()

    text = "客户张三 手机13800138000 身份证440101199001011234 AKIA1234567890ABCDEF"
    runtime_labels = sorted(f.label for f in runtime.detector.detect(text, context).findings)
    manual_labels = sorted(f.label for f in manual.detect(text).findings)
    assert runtime_labels == manual_labels, (runtime_labels, manual_labels)
    _rule("一致性校验")
    print(f"runtime.detector 与本脚本手搭链，标签完全一致：{runtime_labels}")


def main() -> None:
    demo_layer_1_lexical()
    demo_layer_2_normalization()
    demo_layer_3_encoded()
    demo_merge_and_dedup()
    demo_full_pipeline()
    assert_matches_runtime()
    print("\n完。想把这些结论跑成断言，见同目录 test_detection_walkthrough.py。\n")


if __name__ == "__main__":
    assert isinstance(build_detector().detect("x"), DetectionResult)  # 冒烟
    main()
