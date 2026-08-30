"""Build the local Ollama model used by the phone detection Agent."""

from __future__ import annotations

import os
from typing import Any


DEFAULT_MODEL_ID = "qwen3.5:9b"
DEFAULT_API_BASE = "http://127.0.0.1:11436"
DEFAULT_NUM_CTX = 8192


def build_ollama_model(
    model_id: str | None = None,
    *,
    api_base: str | None = None,
    api_key: str | None = None,
    num_ctx: int | None = None,
    **litellm_kwargs: Any,
) -> Any:
    """Return a smolagents ``LiteLLMModel`` configured for Ollama."""

    from smolagents.models import LiteLLMModel

    resolved_id = model_id or os.environ.get("SG_OLLAMA_MODEL") or DEFAULT_MODEL_ID
    resolved_base = api_base or os.environ.get("SG_OLLAMA_API_BASE") or DEFAULT_API_BASE
    resolved_key = api_key or os.environ.get("SG_OLLAMA_API_KEY") or "ollama"
    if num_ctx is not None:
        resolved_ctx = int(num_ctx)
    else:
        env_ctx = os.environ.get("SG_OLLAMA_NUM_CTX")
        resolved_ctx = int(env_ctx) if env_ctx else DEFAULT_NUM_CTX

    if "/" not in resolved_id:
        resolved_id = f"ollama_chat/{resolved_id}"

    return LiteLLMModel(
        model_id=resolved_id,
        api_base=resolved_base,
        api_key=resolved_key,
        num_ctx=resolved_ctx,
        **litellm_kwargs,
    )


__all__ = ["DEFAULT_API_BASE", "DEFAULT_MODEL_ID", "DEFAULT_NUM_CTX", "build_ollama_model"]
