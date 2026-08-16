"""A guarded, transport-agnostic MCP invocation boundary."""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from sensitiveguard.models import DecisionSet, DetectionResult, GuardResult, GuardStage, GuardStatus

from .schema_validator import MCPSchemaValidator, SchemaDefinitionError, SchemaValidationError
from .trust_store import TrustStore, UntrustedMCPServerError


class MCPInvocationError(RuntimeError):
    """A sanitized MCP invocation failure that never includes tool arguments."""


@dataclass(frozen=True, slots=True)
class MCPToolSchema:
    input_schema: Mapping[str, Any] | bool
    output_schema: Mapping[str, Any] | bool | None = None


class MCPGateway:
    """Invoke MCP tools only through an injected callable after two-sided guarding."""

    def __init__(
        self,
        *,
        guard: Any,
        invoker: Any,
        trust_store: TrustStore,
        tool_schemas: Mapping[tuple[str, str], MCPToolSchema | Mapping[str, Any]] | None = None,
        schema_validator: MCPSchemaValidator | None = None,
    ) -> None:
        invoker_methods = (getattr(invoker, "invoke", None), getattr(invoker, "call_tool", None))
        if invoker is None or not (callable(invoker) or any(callable(method) for method in invoker_methods)):
            raise TypeError("MCPGateway requires an injected callable invoker")
        self.guard = guard
        self.invoker = invoker
        self.trust_store = trust_store
        self.tool_schemas = dict(tool_schemas or {})
        self.schema_validator = schema_validator or MCPSchemaValidator()

    def call_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        context: Any,
        input_schema: Mapping[str, Any] | bool | None = None,
        output_schema: Mapping[str, Any] | bool | None = None,
    ) -> GuardResult:
        try:
            trust_policy = self.trust_store.require(server_id, tool_name)
        except UntrustedMCPServerError as exc:
            return self._blocked(str(exc))

        registered = self._resolve_schema(server_id, tool_name)
        # Registered schemas are trusted host configuration. Invocation-time
        # schemas may only fill a missing registration, never weaken one.
        effective_input_schema = registered.input_schema if registered else input_schema
        effective_output_schema = (
            registered.output_schema if registered and registered.output_schema is not None else output_schema
        )
        if effective_input_schema is None:
            return self._blocked("MCP input schema is required")
        if effective_input_schema is True or not isinstance(effective_input_schema, Mapping):
            return self._blocked("MCP input schema must explicitly describe an object")
        try:
            describes_object = self.schema_validator.describes_object(effective_input_schema)
        except (SchemaDefinitionError, TypeError, ValueError):
            describes_object = False
        if not describes_object:
            return self._blocked("MCP input schema must explicitly describe an object")

        if not self._schema_allows(arguments, effective_input_schema):
            return self._blocked("MCP input failed strict schema validation")

        try:
            guarded_input = self.guard.guard_payload(
                deepcopy(dict(arguments)),
                context=context,
                stage=GuardStage.MCP_INPUT,
                destination=trust_policy.destination,
                recipient=trust_policy.recipient,
                tool_name=tool_name,
                record_disclosure=True,
            )
        except Exception:
            return self._blocked("MCP input guard failed")
        if not getattr(guarded_input, "allowed", False):
            return guarded_input
        if not self._schema_allows(guarded_input.content, effective_input_schema):
            return self._blocked("Guarded MCP input no longer matches the tool schema")

        raw_output = self._invoke(server_id, tool_name, guarded_input.content)
        if effective_output_schema is not None and not self._schema_allows(raw_output, effective_output_schema):
            return self._blocked("MCP output failed strict schema validation")

        try:
            guarded_output = self.guard.guard_payload(
                raw_output,
                context=context,
                stage=GuardStage.MCP_OUTPUT,
                destination="agent_runtime",
                recipient=None,
                tool_name=tool_name,
                record_disclosure=False,
            )
        except Exception:
            return self._blocked("MCP output guard failed")
        if not getattr(guarded_output, "allowed", False):
            return guarded_output
        if effective_output_schema is not None and not self._schema_allows(
            guarded_output.content, effective_output_schema
        ):
            return self._blocked("Guarded MCP output no longer matches the tool schema")
        return guarded_output

    invoke = call_tool
    invoke_tool = call_tool

    def _invoke(self, server_id: str, tool_name: str, arguments: Mapping[str, Any]) -> Any:
        failed = False
        result = None
        try:
            if callable(self.invoker):
                result = self.invoker(server_id=server_id, tool_name=tool_name, arguments=deepcopy(arguments))
            elif callable(getattr(self.invoker, "invoke", None)):
                result = self.invoker.invoke(
                    server_id=server_id,
                    tool_name=tool_name,
                    arguments=deepcopy(arguments),
                )
            else:
                result = self.invoker.call_tool(
                    server_id=server_id,
                    tool_name=tool_name,
                    arguments=deepcopy(arguments),
                )
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                failed = True
        except Exception:
            failed = True
        if failed:
            # Raise outside the provider exception handler so neither __cause__
            # nor __context__ retains an exception that may contain raw data.
            raise MCPInvocationError("MCP invocation failed") from None
        return result

    def _resolve_schema(self, server_id: str, tool_name: str) -> MCPToolSchema | None:
        configured = self.tool_schemas.get((server_id, tool_name))
        if configured is None:
            return None
        if isinstance(configured, MCPToolSchema):
            return configured
        if any(key in configured for key in ("input_schema", "output_schema", "inputSchema", "outputSchema")):
            input_schema = configured.get("input_schema", configured.get("inputSchema"))
            if input_schema is None:
                return None
            output_schema = configured.get("output_schema", configured.get("outputSchema"))
            return MCPToolSchema(input_schema=input_schema, output_schema=output_schema)
        return MCPToolSchema(input_schema=configured)

    def _schema_allows(self, payload: Any, schema: Mapping[str, Any] | bool) -> bool:
        try:
            self.schema_validator.validate(payload, schema)
        except (SchemaDefinitionError, SchemaValidationError, TypeError, ValueError):
            return False
        return True

    @staticmethod
    def _blocked(reason: str) -> GuardResult:
        return GuardResult(
            status=GuardStatus.BLOCKED,
            detection=DetectionResult(),
            decisions=DecisionSet(),
            reason=reason,
        )
