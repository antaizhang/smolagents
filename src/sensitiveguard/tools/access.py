"""Data-minimized database and RAG access tools."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from sensitiveguard.models import GuardStage
from sensitiveguard.runtime.error_model import SensitiveGuardError

from .base import SensitiveGuardTool


class SafeQueryDatabaseTool(SensitiveGuardTool):
    name = "safe_query_database"
    description = "Run a read-only structured query with an explicit minimal field projection."
    inputs = {
        "table": {"type": "string", "description": "Host-authorized logical table name."},
        "fields": {"type": "array", "description": "Explicit fields; wildcard projections are forbidden."},
        "filters": {"type": "object", "description": "Structured equality filters; no raw SQL."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        query_executor: Callable[[str, tuple[str, ...], dict[str, Any]], Any],
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._query_executor = query_executor

    def forward(self, table: str, fields: list[str], filters: dict[str, Any]) -> dict[str, Any]:
        task_scope = tuple(self.context.allowed_scope or self.context.required_fields)
        if not task_scope:
            return self.safe_block("No database fields are authorized by the privacy context.")
        try:
            projection = self.gateway.authorization.authorize_projection(
                table,
                fields,
                context_scope=task_scope,
            )
        except SensitiveGuardError as error:
            return self.safe_block(error.public_message)
        if filters:
            try:
                self.gateway.authorization.authorize_projection(
                    table,
                    tuple(filters),
                    context_scope=task_scope,
                )
            except SensitiveGuardError as error:
                return self.safe_block(error.public_message)
        guarded_filters = self.gateway.guard_payload(
            filters,
            self.context,
            GuardStage.DATA_ACQUISITION,
            destination="database",
            tool_name=self.name,
            record_disclosure=False,
        )
        if not guarded_filters.allowed:
            return self.result_payload(guarded_filters)
        try:
            rows = self._query_executor(table, projection, guarded_filters.content)
        except Exception:
            return {"status": "FAILED", "reason": "The protected database query failed."}
        if not self._rows_match_projection(rows, projection):
            return self.safe_block("The database returned fields outside the authorized projection.")
        observation = self.gateway.guard_payload(
            rows,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=self.name,
            record_disclosure=False,
        )
        payload = self.result_payload(observation)
        payload["projection"] = list(projection)
        return payload

    @staticmethod
    def _rows_match_projection(rows: Any, projection: tuple[str, ...]) -> bool:
        allowed = set(projection)
        if isinstance(rows, Mapping):
            row_values = (rows,)
        elif isinstance(rows, (list, tuple)):
            row_values = rows
        else:
            return False
        return all(
            isinstance(row, Mapping) and all(isinstance(key, str) and key in allowed for key in row)
            for row in row_values
        )


class SafeRetrieveRAGTool(SensitiveGuardTool):
    name = "safe_retrieve_rag"
    description = "Retrieve only authorized RAG scopes and sanitize chunks before Agent memory."
    inputs = {
        "query": {"type": "string", "description": "Retrieval query."},
        "top_k": {"type": "integer", "description": "Number of chunks, from 1 through the host maximum."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        retriever: Callable[[str, int, tuple[str, ...]], Any],
        max_top_k: int = 10,
        require_scope_metadata: bool = True,
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._retriever = retriever
        self.max_top_k = max_top_k
        self.require_scope_metadata = require_scope_metadata

    def forward(self, query: str, top_k: int) -> dict[str, Any]:
        scopes = tuple(self.context.allowed_scope)
        if not scopes:
            return self.safe_block("No RAG retrieval scope is authorized by the privacy context.")
        if top_k < 1 or top_k > self.max_top_k:
            return self.safe_block("The requested RAG result count exceeds the configured range.")
        guarded_query = self.gateway.guard_text(
            query,
            self.context,
            GuardStage.DATA_ACQUISITION,
            destination="rag",
            tool_name=self.name,
            record_disclosure=False,
        )
        if not guarded_query.allowed:
            return self.result_payload(guarded_query)
        try:
            chunks = self._retriever(guarded_query.content, top_k, scopes)
        except Exception:
            return {"status": "FAILED", "reason": "The protected RAG retrieval failed."}
        if self.require_scope_metadata and not self._chunks_match_scope(chunks, scopes):
            return self.safe_block("The retriever returned a chunk outside the authorized scope.")
        observation = self.gateway.guard_payload(
            chunks,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=self.name,
            record_disclosure=False,
        )
        return self.result_payload(observation)

    @staticmethod
    def _chunks_match_scope(chunks: Any, scopes: tuple[str, ...]) -> bool:
        if not isinstance(chunks, list):
            return False
        allowed = set(scopes)
        for chunk in chunks:
            if not isinstance(chunk, dict):
                return False
            scope = chunk.get("scope")
            if not isinstance(scope, str) or scope not in allowed:
                return False
        return True
