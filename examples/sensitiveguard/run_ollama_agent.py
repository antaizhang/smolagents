"""Run the SensitiveGuard agent end-to-end against a local Ollama server.

This is the LLM-driven counterpart to ``offline_demo.py`` (which is scripted
and never touches a model). It builds a real SensitiveGuard runtime and lets
an Ollama-hosted model drive the guarded tool calls.

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
    python examples/sensitiveguard/run_ollama_agent.py
"""

from __future__ import annotations

from sensitiveguard import build_ollama_model, create_sensitive_agent
from sensitiveguard.privacy import PrivacyContext


def main() -> None:
    # 1. The LLM: points at your Ollama server via env vars / defaults.
    model = build_ollama_model()

    # 2. The privacy contract for this run: what the agent may see and do.
    context = PrivacyContext(
        task="Detect and mask any sensitive data in the provided customer note.",
        purpose="customer_support_ticket_triage",
        requester="support_agent",
        trust_level="internal",
        allowed_operations=("detect", "mask", "redact", "sanitize"),
    )

    # 3. Assemble the guarded agent. The default tool set covers detection,
    #    masking/redaction/pseudonymization, policy evaluation and auditing.
    agent = create_sensitive_agent(model, context)

    note = (
        "Customer John Smith called about order #A-1042. "
        "Reach him at john.smith@example.com or +1-202-555-0143. "
        "His card on file ends 4242 and his SSN is 123-45-6789."
    )
    task = (
        "Scan the following customer note for sensitive data, then return a masked "
        "version that is safe to store in the ticket system:\n\n" + note
    )

    result = agent.run(task)
    print("\n=== SensitiveGuard result ===")
    print(result)


if __name__ == "__main__":
    main()
