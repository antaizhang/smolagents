"""Run the original SensitiveAgent with one phone-number detection tool.

Prerequisites
-------------
1. ``pip install "smolagents[litellm]"`` and install this package (``pip install -e .``).
2. An Ollama server reachable at the configured base URL with the model pulled:
       ollama list                       # confirm the exact model tag
       curl http://127.0.0.1:11436/api/tags

Configuration (all optional; defaults target port 11436 / qwen3.5:9b)
---------------------------------------------------------------------
    SG_OLLAMA_MODEL, SG_OLLAMA_API_BASE, SG_OLLAMA_NUM_CTX, SG_OLLAMA_API_KEY

Run
---
    python examples/sensitiveguard/run_ollama_agent.py "请联系 13800138000"
"""

from __future__ import annotations

import sys

from sensitiveguard import build_ollama_model, create_sensitive_agent
from sensitiveguard.privacy import PrivacyContext


def main() -> None:
    # 1. The LLM: points at your Ollama server via env vars / defaults.
    model = build_ollama_model()

    # The existing factory signature still accepts a context, but detect-only
    # mode does not construct or execute the old guard/review pipeline.
    context = PrivacyContext(
        task="Determine whether the user input contains a mainland China mobile number.",
        purpose="local_phone_detection",
        requester="local_user",
        destination="local",
        trust_level="local",
        allowed_operations=("detect",),
    )

    # The existing SensitiveToolCallingAgent now exposes one business tool:
    # detect(text). Its result ends the run, so no final_answer tool is added.
    agent = create_sensitive_agent(model, context)

    task = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else input("请输入文本: ").strip()
    if not task:
        raise SystemExit("输入不能为空")

    result = agent.run(task)
    print("\n=== Detection result ===")
    print(result)


if __name__ == "__main__":
    main()
