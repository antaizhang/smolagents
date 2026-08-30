"""Walk one piece of text through the guard, four times, to four destinations.

Runs offline by default: the cascade stops at the pattern and span tiers and no
model is contacted. Pass ``--ollama`` to attach the phone Agent as the top
adjudicating tier and watch how few spans actually reach it.

    python examples/sensitiveguard/run_guard_pipeline.py
    python examples/sensitiveguard/run_guard_pipeline.py --ollama
    python examples/sensitiveguard/run_guard_pipeline.py "自定义文本 13800138000"
"""

from __future__ import annotations

import sys

from sensitiveguard import PhoneAgentDetector, SensitiveGuard, build_ollama_model


SAMPLE = "客户 手机 13800138000，备用 138.0013.8001，邮箱 zhang.san@example.com，请本周回访。"

# destination, caller role, purpose — supplied by whoever owns the request,
# never read out of the content.
ROUTES = [
    ("external_llm", "agent", "tool_call"),
    ("external_llm", "agent", "round_trip"),
    ("internal_log", "service", "observability"),
    ("user_document", "user", "editing"),
]


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def main() -> None:
    arguments = [argument for argument in sys.argv[1:] if argument != "--ollama"]
    use_model = "--ollama" in sys.argv
    text = " ".join(arguments).strip() or SAMPLE

    escalation = PhoneAgentDetector(model=build_ollama_model()) if use_model else None
    guard = SensitiveGuard(escalation=escalation)

    rule("policy and routes")
    if escalation is None:
        print(
            "Running without the top tier. Spans the patterns cannot settle stay ambiguous,\n"
            "and the policy decides what an ambiguous span is worth per destination —\n"
            "held back from an external model, allowed to stay inside. Re-run with --ollama\n"
            "to let the phone Agent adjudicate them.\n"
        )
    print(guard.describe())
    failures = guard.self_test()
    print(f"\npolicy self-test: {'passed' if not failures else failures}")

    print(f"\ninput: {text}")

    for destination, caller_role, purpose in ROUTES:
        rule(f"{destination}  caller={caller_role}  purpose={purpose}")
        result = guard.inspect(text, destination=destination, caller_role=caller_role, purpose=purpose)
        if result.released:
            print(f"released: {result.released_text}")
        else:
            print("withheld — nothing was released:")
            for decision in (*result.disposition.blocked, *result.disposition.held):
                print(f"  {decision.action.value} {decision.label} by {decision.rule_id}: {decision.reason}")
        print(f"model calls spent: {result.detection.escalation_calls}")
        if result.review is not None and not result.review.ok:
            print(result.review.describe())

        if purpose == "round_trip" and result.released_text:
            reply = f"已安排回访：{result.released_text}"
            print(f"restored: {guard.restore(reply).text}")

    rule("why was that one masked?")
    audit = guard.inspect(text, destination="external_llm", caller_role="agent", purpose="tool_call")
    if audit.decisions:
        print(audit.decisions[0].explain())
    else:
        print("nothing was detected in this input")


if __name__ == "__main__":
    main()
