"""OpenAI-compatible SensitiveGuard endpoint for BFCL V4 generation.

BFCL remains responsible for loading cases and evaluating generated function
calls. Point BFCL's pre-existing OpenAI-compatible endpoint mode at this server;
the server forwards model generation to the configured local Ollama model and
applies B3/B4 argument/intent guards before returning tool calls.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from typing import Any

from sensitiveguard.dynamic_agent import resolve_request_intent
from sensitiveguard.llm import build_ollama_model
from sensitiveguard.models import GuardStage
from smolagents.models import ChatMessage, MessageRole, parse_json_if_needed

from .tools import (
    RawExternalTool,
    build_external_context,
    build_external_runtime,
    infer_external_tool_spec,
    json_schema_to_smol_inputs,
)


def _role(value: str) -> MessageRole:
    mapping = {
        "system": MessageRole.SYSTEM,
        "user": MessageRole.USER,
        "assistant": MessageRole.ASSISTANT,
        "tool": MessageRole.TOOL_RESPONSE,
    }
    return mapping.get(str(value).lower(), MessageRole.USER)


def _message_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "".join(parts)
    return "" if value is None else str(value)


def _generate_bfcl_response(payload: dict[str, Any], *, runtime_label: str, model: Any) -> dict[str, Any]:
    label = runtime_label.upper()
    if label not in {"B0", "B3", "B4"}:
        raise ValueError("BFCL runtime must be B0, B3, or B4")
    raw_tools = payload.get("tools") or []
    schema_tools = []
    specs = []
    for item in raw_tools:
        function = item.get("function", {}) if isinstance(item, dict) else {}
        name = str(function.get("name") or "unknown_tool")
        description = str(function.get("description") or name)
        inputs = json_schema_to_smol_inputs(function.get("parameters") or {})
        spec = infer_external_tool_spec(name, description, inputs)
        specs.append(spec)
        schema_tools.append(RawExternalTool(spec, lambda arguments: arguments))

    messages = [
        ChatMessage(role=_role(item.get("role", "user")), content=_message_content(item.get("content")))
        for item in (payload.get("messages") or [])
        if isinstance(item, dict)
    ]
    response = model.generate(messages, tools_to_call_from=schema_tools or None)
    tool_calls = []

    runtime = None
    active_intent = None
    if label != "B0":
        user_text = "\n".join(
            _message_content(item.get("content"))
            for item in (payload.get("messages") or [])
            if isinstance(item, dict) and item.get("role") == "user"
        ) or "Select the correct tool for this request."
        context = build_external_context(
            user_text,
            specs,
            purpose="bfcl_function_call_evaluation",
            run_id=f"bfcl-{label.lower()}-{uuid.uuid4().hex}",
        )
        runtime = build_external_runtime(context, specs)
        parent = runtime.intent_resolver.resolve(context)
        active_intent = (
            resolve_request_intent(
                runtime.intent_resolver,
                context,
                user_text,
                parent=parent,
                capability_operations={spec.name: spec.operation for spec in specs},
            )
            if label == "B4"
            else parent
        )

    for index, call in enumerate(response.tool_calls or (), start=1):
        name = str(call.function.name)
        arguments = parse_json_if_needed(call.function.arguments or {})
        if not isinstance(arguments, dict):
            arguments = {}
        if runtime is not None:
            allowed_capabilities = {item.casefold() for item in active_intent.allowed_capabilities}
            if label == "B4" and allowed_capabilities and name.casefold() not in allowed_capabilities:
                continue
            guarded = runtime.gateway.guard_payload(
                arguments,
                runtime.context,
                GuardStage.TOOL_INPUT,
                destination="internal_benchmark",
                tool_name=name,
                record_disclosure=False,
            )
            if not guarded.allowed or not isinstance(guarded.content, dict):
                continue
            arguments = dict(guarded.content)
        tool_calls.append(
            {
                "id": str(call.id or f"call_{index}"),
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))},
            }
        )

    content = None if tool_calls else _message_content(response.content)
    if runtime is not None and content:
        guarded = runtime.gateway.guard_text(
            content,
            runtime.context,
            GuardStage.FINAL_OUTPUT,
            destination="requester",
            tool_name="bfcl_text_response",
            record_disclosure=False,
        )
        content = str(guarded.content) if guarded.allowed else ""

    return {
        "id": "chatcmpl-" + uuid.uuid4().hex,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": f"sensitiveguard-{label.lower()}",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, "tool_calls": tool_calls or None},
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def create_bfcl_app(*, runtime_label: str = "B4", model: Any | None = None):
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError as error:
        raise RuntimeError("BFCL bridge server requires `pip install fastapi uvicorn`") from error

    app = FastAPI(title="SensitiveGuard BFCL Bridge")
    resolved_model = model or build_ollama_model()

    @app.get("/v1/models")
    def models():
        return {"object": "list", "data": [{"id": f"sensitiveguard-{runtime_label.lower()}", "object": "model"}]}

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]):
        if payload.get("stream"):
            raise HTTPException(status_code=400, detail="BFCL bridge currently requires stream=false")
        try:
            return _generate_bfcl_response(payload, runtime_label=runtime_label, model=resolved_model)
        except Exception as error:
            raise HTTPException(status_code=500, detail=f"SensitiveGuard BFCL generation failed: {type(error).__name__}") from None

    return app


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m sensitiveguard.eval.external.bfcl")
    parser.add_argument("--runtime", choices=("B0", "B3", "B4"), default="B4")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8011)
    args = parser.parse_args()
    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError("BFCL bridge server requires `pip install fastapi uvicorn`") from error
    uvicorn.run(create_bfcl_app(runtime_label=args.runtime), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["create_bfcl_app"]
