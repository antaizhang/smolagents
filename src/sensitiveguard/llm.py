"""Shared LLM factory so the whole project can run on a local Ollama server.

SensitiveGuard injects its LLM from the outside (see
:func:`sensitiveguard.create_sensitive_agent`), so pointing the *entire*
project at Ollama just means building every agent's model with the helper
below. Defaults target a local Ollama serving ``qwen3.5:9b`` on port 11436;
override any of them with environment variables or keyword arguments.

Environment variables
---------------------
``SG_OLLAMA_MODEL``      Ollama model tag, e.g. ``qwen3.5:9b`` (as shown by ``ollama list``).
``SG_OLLAMA_API_BASE``   Base URL of the Ollama server, e.g. ``http://127.0.0.1:11436``.
``SG_OLLAMA_NUM_CTX``    Context window; Ollama's 2048 default is too small for agents.
``SG_OLLAMA_API_KEY``    Ignored by Ollama but required by the client; any non-empty value.

Usage
-----
    from sensitiveguard.llm import build_ollama_model
    model = build_ollama_model()  # honors the env vars above
"""

from __future__ import annotations

import os
from typing import Any

# Defaults match the target deployment: Ollama on port 11436 serving qwen3.5:9b.
DEFAULT_MODEL_ID = "qwen3.5:9b"
DEFAULT_API_BASE = "http://127.0.0.1:11436"
DEFAULT_NUM_CTX = 8192

__all__ = ["build_ollama_model", "DEFAULT_MODEL_ID", "DEFAULT_API_BASE", "DEFAULT_NUM_CTX"]


def build_ollama_model(
    model_id: str | None = None,
    *,
    api_base: str | None = None,
    api_key: str | None = None,
    num_ctx: int | None = None,
    **litellm_kwargs: Any,
) -> Any:
    """Build a smolagents ``LiteLLMModel`` bound to a local Ollama server.

    Arguments take precedence over environment variables, which take
    precedence over the module defaults. The returned model is a normal
    smolagents model and can be handed to any agent, including
    :func:`sensitiveguard.create_sensitive_agent`.
    """
    # Imported lazily so importing this module never hard-requires litellm.
    from smolagents import LiteLLMModel

    resolved_id = model_id or os.environ.get("SG_OLLAMA_MODEL") or DEFAULT_MODEL_ID
    resolved_base = api_base or os.environ.get("SG_OLLAMA_API_BASE") or DEFAULT_API_BASE
    resolved_key = api_key or os.environ.get("SG_OLLAMA_API_KEY") or "ollama"

    if num_ctx is not None:
        resolved_ctx = int(num_ctx)
    else:
        env_ctx = os.environ.get("SG_OLLAMA_NUM_CTX")
        resolved_ctx = int(env_ctx) if env_ctx else DEFAULT_NUM_CTX

    # LiteLLM routes to Ollama's chat API through the ``ollama_chat/`` prefix.
    # Accept a bare tag (``qwen3.5:9b``) or an already-prefixed id.
    if "/" not in resolved_id:
        resolved_id = f"ollama_chat/{resolved_id}"

    return LiteLLMModel(
        model_id=resolved_id,
        api_base=resolved_base,
        api_key=resolved_key,
        num_ctx=resolved_ctx,
        **litellm_kwargs,
    )
