"""One-tool Ollama demo for mainland China mobile-number detection.

Only the ``detect`` business tool is exposed to the model. This example does
not use planning, Agent memory, intent TTLs, deterministic security review, or
the automatic ``final_answer`` tool.

Run:
    python examples/sensitiveguard/run_ollama_phone_agent.py "请联系 13800138000"
"""

from __future__ import annotations

import json
import sys

from sensitiveguard import build_ollama_model, detect
from smolagents import ChatMessage, MessageRole, parse_json_if_needed, tool


def main() -> None:
    user_text = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else input("请输入文本: ").strip()
    if not user_text:
        raise SystemExit("输入不能为空")

    detect_tool = tool(detect)
    model = build_ollama_model(max_tokens=128, reasoning_effort="none")
    response = model.generate(
        [
            ChatMessage(
                role=MessageRole.USER,
                content=[
                    {
                        "type": "text",
                        "text": (
                            "Call detect exactly once with the complete user input. "
                            "Do not alter, shorten, or answer the input directly.\n\n"
                            f"User input:\n{user_text}"
                        ),
                    }
                ],
            )
        ],
        tools_to_call_from=[detect_tool],
        tool_choice="required",
    )

    calls = response.tool_calls or []
    if len(calls) != 1 or calls[0].function.name != "detect":
        raise RuntimeError("The model did not return exactly one detect tool call")

    arguments = parse_json_if_needed(calls[0].function.arguments)
    if not isinstance(arguments, dict) or arguments.get("text") != user_text:
        raise RuntimeError("The model changed the input instead of forwarding it intact")

    result = detect(text=user_text)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
