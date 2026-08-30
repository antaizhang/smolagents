"""Run the one-tool phone detection Agent with Ollama."""

from __future__ import annotations

import sys

from sensitiveguard import PhoneDetectionAgent, build_ollama_model


def main() -> None:
    text = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else input("请输入文本: ").strip()
    if not text:
        raise SystemExit("输入不能为空")

    agent = PhoneDetectionAgent(model=build_ollama_model())
    result = agent.run(text)
    print("\n=== Detection result ===")
    print(result)


if __name__ == "__main__":
    main()
