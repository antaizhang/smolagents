"""Deterministic English/Chinese intent resolution from trusted context."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

from .models import (
    Effect,
    IntentOperation,
    IntentSpec,
    _coerce_enum,
    _scope_is_narrower,
    _signed_intent_id,
)


_OPERATION_KEYWORDS: dict[IntentOperation, tuple[str, ...]] = {
    IntentOperation.READ: (
        "read",
        "inspect",
        "view",
        "get",
        "load",
        "读取",
        "查看",
        "获取",
        "加载",
    ),
    IntentOperation.QUERY: ("query", "select", "database", "查询", "数据库", "统计"),
    IntentOperation.RETRIEVE: ("retrieve", "search", "rag", "检索", "搜索", "召回"),
    IntentOperation.SCAN: ("scan", "inventory", "扫描", "盘点"),
    IntentOperation.DETECT: ("detect", "identify", "classify", "检测", "识别", "分类"),
    IntentOperation.ANALYZE: ("analyze", "analyse", "analysis", "evaluate", "分析", "评估", "统计"),
    IntentOperation.SUMMARIZE: ("summarize", "summary", "aggregate", "总结", "摘要", "汇总"),
    IntentOperation.TRANSFORM: (
        "transform",
        "sanitize",
        "mask",
        "redact",
        "tokenize",
        "pseudonymize",
        "脱敏",
        "掩码",
        "遮盖",
        "令牌化",
        "匿名化",
    ),
    IntentOperation.WRITE: (
        "write",
        "save",
        "copy",
        "create",
        "remediate",
        "写入",
        "保存",
        "复制",
        "创建",
        "修复",
    ),
    IntentOperation.SEND: (
        "send",
        "post",
        "upload",
        "email",
        "message",
        "export",
        "发送",
        "上传",
        "邮件",
        "消息",
        "外发",
        "导出",
    ),
    IntentOperation.DELETE: ("delete", "remove", "erase", "删除", "移除", "擦除"),
    IntentOperation.EXECUTE: ("execute", "run", "shell", "command", "执行", "运行", "命令"),
    IntentOperation.HANDOFF: ("handoff", "delegate", "transfer", "交接", "委派", "转交"),
}

_CAPABILITIES_BY_OPERATION: dict[IntentOperation, frozenset[str]] = {
    IntentOperation.READ: frozenset({"safe_read_file", "safe_query_database", "safe_retrieve_rag"}),
    IntentOperation.QUERY: frozenset({"safe_query_database"}),
    IntentOperation.RETRIEVE: frozenset({"safe_retrieve_rag"}),
    IntentOperation.SCAN: frozenset({"scan_directory", "scan_file"}),
    IntentOperation.DETECT: frozenset({"detect_sensitive_data", "evaluate_data_policy", "verify_sanitized_file"}),
    IntentOperation.ANALYZE: frozenset({"detect_sensitive_data", "evaluate_data_policy", "safe_llm_call"}),
    IntentOperation.SUMMARIZE: frozenset({"safe_llm_call", "final_answer"}),
    IntentOperation.TRANSFORM: frozenset(
        {
            "mask_text",
            "pseudonymize_text",
            "redact_text",
            "sanitize_file",
            "sanitize_text",
            "tokenize_sensitive_data",
        }
    ),
    IntentOperation.WRITE: frozenset({"remediate_sensitive_file", "sanitize_file"}),
    IntentOperation.SEND: frozenset({"safe_http_post", "safe_llm_call", "safe_send_email", "safe_send_message"}),
    # Destructive/code execution capabilities must always be explicitly supplied
    # by trusted host configuration; natural-language inference never grants one.
    IntentOperation.DELETE: frozenset(),
    IntentOperation.EXECUTE: frozenset(),
    IntentOperation.HANDOFF: frozenset({"agent_handoff", "mcp_call"}),
}

_EFFECTS_BY_OPERATION: dict[IntentOperation, frozenset[Effect]] = {
    IntentOperation.READ: frozenset({Effect.READ}),
    IntentOperation.QUERY: frozenset({Effect.READ}),
    IntentOperation.RETRIEVE: frozenset({Effect.READ}),
    IntentOperation.SCAN: frozenset({Effect.READ}),
    IntentOperation.DETECT: frozenset({Effect.READ}),
    IntentOperation.ANALYZE: frozenset({Effect.READ, Effect.MODEL, Effect.EXTERNAL}),
    IntentOperation.SUMMARIZE: frozenset({Effect.READ, Effect.MODEL, Effect.EXTERNAL}),
    IntentOperation.TRANSFORM: frozenset({Effect.READ, Effect.WRITE}),
    IntentOperation.WRITE: frozenset({Effect.READ, Effect.WRITE}),
    IntentOperation.SEND: frozenset({Effect.NETWORK, Effect.MESSAGE, Effect.MODEL, Effect.EXTERNAL, Effect.WRITE}),
    IntentOperation.DELETE: frozenset({Effect.DELETE}),
    IntentOperation.EXECUTE: frozenset({Effect.EXECUTE, Effect.READ}),
    IntentOperation.HANDOFF: frozenset({Effect.HANDOFF, Effect.EXTERNAL}),
}


class RuleBasedIntentResolver:
    """Compile trusted task context into a signed, raw-free intent envelope."""

    def __init__(
        self,
        *,
        key: bytes | None = None,
        ttl_seconds: float = 300.0,
        clock: Any = time.time,
    ) -> None:
        signing_key = key or secrets.token_bytes(32)
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            raise ValueError("Intent HMAC key must contain at least 16 bytes")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise TypeError("Intent TTL must be numeric")
        if not math.isfinite(float(ttl_seconds)) or ttl_seconds <= 0:
            raise ValueError("Intent TTL must be finite and positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._key = signing_key
        self.ttl_seconds = float(ttl_seconds)
        self._clock = clock

    def resolve(
        self,
        context: Any,
        *,
        version: int | None = None,
        ttl_seconds: float | None = None,
    ) -> IntentSpec:
        task = self._required_text(context, "task")
        purpose = self._required_text(context, "purpose")
        run_id = self._required_text(context, "run_id")
        now = float(self._clock())
        if isinstance(ttl_seconds, bool):
            raise TypeError("Intent TTL must be numeric")
        ttl = self.ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        if not math.isfinite(now) or now < 0:
            raise ValueError("Intent clock returned an invalid timestamp")
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("Intent TTL must be finite and positive")

        inferred = self._infer_operations(f"{task}\n{purpose}")
        explicit_operations = self._context_value(context, "allowed_operations", None)
        normalized_explicit = (
            self._operations(explicit_operations, "allowed_operations") if explicit_operations is not None else ()
        )
        # Newer contexts expose an empty tuple by default.  Treat that default
        # exactly like the field being absent so older callers retain rule-based
        # inference.  A host that wants to deny inferred operations should use
        # denied_operations explicitly.
        operations = normalized_explicit or inferred
        denied_operation_values = self._values(
            self._context_value(context, "denied_operations", ()), field_name="denied_operations"
        )
        denied_operations = (
            set(IntentOperation)
            if any(str(value).strip() == "*" for value in denied_operation_values)
            else set(self._operations(denied_operation_values, "denied_operations"))
        )
        operations = tuple(sorted(set(operations) - denied_operations, key=lambda item: item.value))

        capabilities = self._resolve_capabilities(context, operations)
        effects = self._resolve_effects(context, operations)
        fields, forbidden_fields = self._resolve_fields(context)
        destinations = self._resolve_scope(context, "allowed_destinations", "destination", "denied_destinations")
        recipients = self._resolve_scope(context, "allowed_recipients", "recipient", "denied_recipients")
        goal_digest = self._goal_digest(task, purpose)
        resolved_version = self._context_value(context, "intent_version", 1) if version is None else version
        context_expiry = self._context_value(context, "intent_expires_at", None)
        expires_at = now + ttl
        if context_expiry is not None:
            explicit_expiry = float(context_expiry)
            if not math.isfinite(explicit_expiry) or explicit_expiry <= now:
                raise ValueError("Trusted context intent_expires_at must be in the future")
            expires_at = min(expires_at, explicit_expiry)

        unsigned = IntentSpec(
            intent_id="unsigned",
            run_id=run_id,
            version=resolved_version,
            goal_digest=goal_digest,
            issued_at=now,
            expires_at=expires_at,
            allowed_operations=operations,
            allowed_capabilities=capabilities,
            allowed_effects=effects,
            allowed_fields=fields,
            forbidden_fields=forbidden_fields,
            allowed_destinations=destinations,
            allowed_recipients=recipients,
        )
        return replace(unsigned, intent_id=_signed_intent_id(unsigned, self._key))

    resolve_intent = resolve
    build = resolve

    def narrow(
        self,
        parent: IntentSpec,
        *,
        allowed_operations: Iterable[IntentOperation | str] | None = None,
        allowed_capabilities: Iterable[str] | None = None,
        allowed_effects: Iterable[Effect | str] | None = None,
        allowed_fields: Iterable[str] | None = None,
        forbidden_fields: Iterable[str] | None = None,
        allowed_destinations: Iterable[str] | None = None,
        allowed_recipients: Iterable[str] | None = None,
        expires_at: float | None = None,
    ) -> IntentSpec:
        """Sign a child plan after proving that every permission is narrower."""

        if not isinstance(parent, IntentSpec):
            raise TypeError("parent must be an IntentSpec")
        now = float(self._clock())
        if not hmac.compare_digest(parent.intent_id, _signed_intent_id(parent, self._key)):
            raise ValueError("The parent intent signature is invalid")
        if now < parent.issued_at or now >= parent.expires_at:
            raise ValueError("The parent intent is not active")
        child_forbidden = set(parent.forbidden_fields)
        if forbidden_fields is not None:
            child_forbidden.update(str(value).strip().casefold() for value in forbidden_fields)
        unsigned = IntentSpec(
            intent_id="unsigned",
            run_id=parent.run_id,
            version=parent.version,
            goal_digest=parent.goal_digest,
            issued_at=max(now, parent.issued_at),
            expires_at=min(parent.expires_at, float(expires_at) if expires_at is not None else parent.expires_at),
            allowed_operations=parent.allowed_operations if allowed_operations is None else tuple(allowed_operations),
            allowed_capabilities=(
                parent.allowed_capabilities if allowed_capabilities is None else tuple(allowed_capabilities)
            ),
            allowed_effects=parent.allowed_effects if allowed_effects is None else tuple(allowed_effects),
            allowed_fields=parent.allowed_fields if allowed_fields is None else tuple(allowed_fields),
            forbidden_fields=tuple(child_forbidden),
            allowed_destinations=(
                parent.allowed_destinations if allowed_destinations is None else tuple(allowed_destinations)
            ),
            allowed_recipients=parent.allowed_recipients if allowed_recipients is None else tuple(allowed_recipients),
            parent_intent_id=parent.intent_id,
        )
        self._require_narrower(parent, unsigned)
        return replace(unsigned, intent_id=_signed_intent_id(unsigned, self._key))

    narrow_plan = narrow

    def intent_guard(self, **kwargs: Any) -> Any:
        """Create a guard sharing this resolver's signing key and clock."""

        from .guard import IntentGuard

        return IntentGuard(key=self._key, clock=self._clock, **kwargs)

    def _goal_digest(self, task: str, purpose: str) -> str:
        raw = json.dumps(
            {"purpose": purpose, "task": task},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._key, b"SensitiveGuard.Goal.v1\0" + raw, hashlib.sha256).hexdigest()

    @staticmethod
    def _context_value(context: Any, name: str, default: Any = None) -> Any:
        if isinstance(context, Mapping):
            return context.get(name, default)
        return getattr(context, name, default)

    def _required_text(self, context: Any, name: str) -> str:
        value = self._context_value(context, name, None)
        if value is None or not str(value).strip():
            raise ValueError(f"Trusted context {name} must not be empty")
        return str(value).strip()

    @staticmethod
    def _values(value: Any, *, field_name: str) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        try:
            return tuple(value)
        except TypeError as error:
            raise TypeError(f"Trusted context {field_name} must be iterable") from error

    def _operations(self, values: Any, field_name: str) -> tuple[IntentOperation, ...]:
        result = {
            _coerce_enum(value, IntentOperation, field_name=field_name)
            for value in self._values(values, field_name=field_name)
        }
        return tuple(sorted(result, key=lambda item: item.value))

    @staticmethod
    def _infer_operations(text: str) -> tuple[IntentOperation, ...]:
        casefolded = text.casefold()
        operations = set()
        for operation, keywords in _OPERATION_KEYWORDS.items():
            for keyword in keywords:
                if keyword.isascii():
                    if re.search(rf"(?<![a-z0-9_]){re.escape(keyword)}(?![a-z0-9_])", casefolded):
                        operations.add(operation)
                        break
                elif keyword in text:
                    operations.add(operation)
                    break
        return tuple(sorted(operations, key=lambda item: item.value))

    def _resolve_capabilities(self, context: Any, operations: tuple[IntentOperation, ...]) -> tuple[str, ...]:
        explicit = self._context_value(context, "allowed_capabilities", None)
        explicit_values = () if explicit is None else self._values(explicit, field_name="allowed_capabilities")
        if not explicit_values:
            values = (
                set().union(*(_CAPABILITIES_BY_OPERATION[operation] for operation in operations))
                if operations
                else set()
            )
        else:
            values = {str(value).strip().casefold() for value in explicit_values}
        denied = {
            str(value).strip().casefold()
            for value in self._values(
                self._context_value(context, "denied_capabilities", ()), field_name="denied_capabilities"
            )
        }
        if any(not value for value in values | denied):
            raise ValueError("Capability names must not be empty")
        if "*" in denied:
            return ()
        return tuple(sorted(values - denied))

    def _resolve_effects(self, context: Any, operations: tuple[IntentOperation, ...]) -> tuple[Effect, ...]:
        explicit = self._context_value(context, "allowed_effects", None)
        explicit_values = () if explicit is None else self._values(explicit, field_name="allowed_effects")
        if not explicit_values:
            values = (
                set().union(*(_EFFECTS_BY_OPERATION[operation] for operation in operations)) if operations else set()
            )
        else:
            values = {_coerce_enum(value, Effect, field_name="allowed_effects") for value in explicit_values}
        denied_values = self._values(self._context_value(context, "denied_effects", ()), field_name="denied_effects")
        denied = (
            set(Effect)
            if any(str(value).strip() == "*" for value in denied_values)
            else {_coerce_enum(value, Effect, field_name="denied_effects") for value in denied_values}
        )
        return tuple(sorted(values - denied, key=lambda item: item.value))

    def _resolve_fields(self, context: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
        explicit = self._context_value(context, "allowed_fields", None)
        scope = self._normalized_strings(self._context_value(context, "allowed_scope", ()), "allowed_scope")
        required = self._normalized_strings(self._context_value(context, "required_fields", ()), "required_fields")
        optional = self._normalized_strings(self._context_value(context, "optional_fields", ()), "optional_fields")
        forbidden = self._normalized_strings(self._context_value(context, "forbidden_fields", ()), "forbidden_fields")
        if explicit is not None:
            fields = self._normalized_strings(explicit, "allowed_fields")
        elif required or optional:
            fields = required | optional
            if scope and "*" not in scope:
                fields &= scope
        else:
            # Older PrivacyContext objects only carried allowed_scope.  Treat it
            # as the trusted ceiling so the resolver remains backward compatible.
            fields = set(scope)
        if "*" in forbidden:
            fields = set()
        elif "*" not in fields:
            fields -= forbidden
        return tuple(sorted(fields)), tuple(sorted(forbidden))

    def _resolve_scope(
        self,
        context: Any,
        plural_name: str,
        singular_name: str,
        denied_name: str,
    ) -> tuple[str, ...]:
        explicit = self._context_value(context, plural_name, None)
        if explicit is None or not self._values(explicit, field_name=plural_name):
            singular = self._context_value(context, singular_name, None)
            values = set() if singular is None else {str(singular).strip().casefold()}
        else:
            values = self._normalized_strings(explicit, plural_name)
        denied = self._normalized_strings(self._context_value(context, denied_name, ()), denied_name)
        if any(not value for value in values | denied):
            raise ValueError(f"Trusted context {plural_name} contains an empty value")
        if "*" in denied:
            return ()
        return tuple(sorted(values - denied))

    def _normalized_strings(self, values: Any, field_name: str) -> set[str]:
        result = {str(value).strip().casefold() for value in self._values(values, field_name=field_name)}
        if any(not value for value in result):
            raise ValueError(f"Trusted context {field_name} contains an empty value")
        return result

    @staticmethod
    def _require_narrower(parent: IntentSpec, child: IntentSpec) -> None:
        scopes = (
            (child.allowed_operations, parent.allowed_operations),
            (child.allowed_capabilities, parent.allowed_capabilities),
            (child.allowed_effects, parent.allowed_effects),
            (child.allowed_fields, parent.allowed_fields),
            (child.allowed_destinations, parent.allowed_destinations),
            (child.allowed_recipients, parent.allowed_recipients),
        )
        if not all(_scope_is_narrower(child_values, parent_values) for child_values, parent_values in scopes):
            raise ValueError("A child plan may only narrow its parent intent")
        if not set(parent.forbidden_fields) <= set(child.forbidden_fields):
            raise ValueError("A child plan may not remove forbidden fields")


# A concise alias for callers that do not need to distinguish resolver types.
IntentResolver = RuleBasedIntentResolver


__all__ = ["IntentResolver", "RuleBasedIntentResolver"]
