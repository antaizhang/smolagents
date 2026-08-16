"""Explicit trust policies for MCP servers and their tools."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Any


class UntrustedMCPServerError(PermissionError):
    """Raised when an MCP server or tool is not explicitly authorized."""


@dataclass(frozen=True, slots=True)
class MCPServerPolicy:
    server_id: str
    allowed_tools: frozenset[str]
    destination: str
    recipient: str

    def allows(self, tool_name: str) -> bool:
        return "*" in self.allowed_tools or tool_name in self.allowed_tools


class TrustStore:
    """In-memory allow-list. Unknown servers and unspecified tools are denied."""

    def __init__(
        self,
        entries: Mapping[str, MCPServerPolicy | Mapping[str, Any] | Iterable[str]] | None = None,
    ) -> None:
        self._entries: dict[str, MCPServerPolicy] = {}
        self._lock = RLock()
        for server_id, entry in (entries or {}).items():
            if isinstance(entry, MCPServerPolicy):
                if entry.server_id != server_id:
                    raise ValueError("Trust entry key must match policy.server_id")
                self.trust(
                    server_id,
                    allowed_tools=entry.allowed_tools,
                    destination=entry.destination,
                    recipient=entry.recipient,
                )
            elif isinstance(entry, Mapping):
                self.trust(
                    server_id,
                    allowed_tools=entry.get("allowed_tools", ()),
                    destination=entry.get("destination"),
                    recipient=entry.get("recipient"),
                )
            else:
                self.trust(server_id, allowed_tools=entry)

    def trust(
        self,
        server_id: str,
        *,
        allowed_tools: Iterable[str],
        destination: str | None = None,
        recipient: str | None = None,
    ) -> MCPServerPolicy:
        self._validate_identifier(server_id, "server_id")
        if isinstance(allowed_tools, str):
            allowed_tools = (allowed_tools,)
        tools = frozenset(str(tool).strip() for tool in allowed_tools if str(tool).strip())
        if not tools:
            raise ValueError("A trusted MCP server must explicitly allow at least one tool")
        policy = MCPServerPolicy(
            server_id=server_id,
            allowed_tools=tools,
            destination=destination or f"mcp://{server_id}",
            recipient=recipient or server_id,
        )
        with self._lock:
            self._entries[server_id] = policy
        return policy

    def revoke(self, server_id: str) -> bool:
        with self._lock:
            return self._entries.pop(server_id, None) is not None

    def get_policy(self, server_id: str) -> MCPServerPolicy | None:
        with self._lock:
            return self._entries.get(server_id)

    def is_trusted(self, server_id: str) -> bool:
        return self.get_policy(server_id) is not None

    def is_tool_allowed(self, server_id: str, tool_name: str) -> bool:
        policy = self.get_policy(server_id)
        return policy is not None and policy.allows(tool_name)

    def require(self, server_id: str, tool_name: str) -> MCPServerPolicy:
        policy = self.get_policy(server_id)
        if policy is None:
            raise UntrustedMCPServerError("MCP server is not present in the trust store")
        if not policy.allows(tool_name):
            raise UntrustedMCPServerError("MCP tool is not allowed for this server")
        return policy

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
            raise ValueError(f"{label} must be a non-empty string of at most 256 characters")
