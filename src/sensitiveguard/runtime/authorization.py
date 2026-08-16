"""Authorization checks for paths, destinations, URLs and database projections."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .error_model import AuthorizationError


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(slots=True)
class AuthorizationPolicy:
    """Host-controlled capabilities. None of these values should come from the LLM."""

    allowed_roots: tuple[Path | str, ...] = ()
    allowed_tools: frozenset[str] | None = None
    denied_tools: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"python_interpreter", "raw_http_post", "raw_database", "raw_external_llm", "raw_email_api"}
        )
    )
    allowed_http_hosts: frozenset[str] = field(default_factory=frozenset)
    allow_http: bool = False
    allow_private_networks: bool = False
    reject_symlinks: bool = True
    allowed_database_tables: dict[str, frozenset[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.allowed_roots = tuple(Path(root).expanduser().resolve() for root in self.allowed_roots)
        self.allowed_http_hosts = frozenset(host.lower().rstrip(".") for host in self.allowed_http_hosts)

    def authorize_tool(self, tool_name: str) -> None:
        if tool_name in self.denied_tools:
            raise AuthorizationError(details={"tool": tool_name})
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            raise AuthorizationError(details={"tool": tool_name})

    def authorize_path(self, path: str | Path, *, write: bool = False, must_exist: bool = True) -> Path:
        candidate = Path(path).expanduser()
        if self.reject_symlinks:
            current = candidate if candidate.is_absolute() else Path.cwd() / candidate
            for part in (current, *current.parents):
                if part.exists() and part.is_symlink():
                    raise AuthorizationError("Symbolic links are not allowed in protected file paths.")

        if must_exist and not candidate.exists():
            raise AuthorizationError("The protected path does not exist.")
        if write and candidate.exists() and candidate.is_symlink():
            raise AuthorizationError("Refusing to write through a symbolic link.")

        resolved = candidate.resolve(strict=must_exist)
        if not self.allowed_roots:
            raise AuthorizationError("No protected filesystem roots have been configured.")
        if not any(resolved == root or _is_relative_to(resolved, root) for root in self.allowed_roots):
            raise AuthorizationError("The protected path is outside the configured roots.")
        return resolved

    def authorize_copy(self, source: str | Path, destination: str | Path) -> tuple[Path, Path]:
        source_path = self.authorize_path(source, must_exist=True)
        destination_path = self.authorize_path(destination, write=True, must_exist=False)
        if source_path == destination_path:
            raise AuthorizationError("A sanitized copy cannot overwrite the source file.")
        return source_path, destination_path

    def authorize_url(self, url: str) -> str:
        parsed = urlsplit(url)
        allowed_schemes = {"https"} | ({"http"} if self.allow_http else set())
        if parsed.scheme.lower() not in allowed_schemes:
            raise AuthorizationError("The URL scheme is not allowed.")
        if parsed.username or parsed.password:
            raise AuthorizationError("Credentials in protected URLs are not allowed.")
        if not parsed.hostname:
            raise AuthorizationError("The URL has no valid host.")

        hostname = parsed.hostname.lower().rstrip(".")
        if hostname not in self.allowed_http_hosts:
            raise AuthorizationError("The URL host is not in the egress allowlist.")
        if not self.allow_private_networks and self._resolves_to_private_address(hostname):
            raise AuthorizationError("Private and local network destinations are not allowed.")
        return url

    @staticmethod
    def _resolves_to_private_address(hostname: str) -> bool:
        if hostname == "localhost" or hostname.endswith(".localhost"):
            return True
        try:
            literal = ipaddress.ip_address(hostname)
            addresses = [literal]
        except ValueError:
            try:
                addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(hostname, None)]
            except (OSError, ValueError):
                # Do not let the transport retry with a different resolver or
                # after a DNS-rebinding change. An address that cannot be
                # classified here is unsafe by default.
                return True
        return any(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            for address in addresses
        )

    def authorize_projection(
        self,
        table: str,
        fields: list[str] | tuple[str, ...],
        *,
        context_scope: list[str] | tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        if not fields or any(field.strip() == "*" for field in fields):
            raise AuthorizationError("Wildcard or empty database projections are not allowed.")
        configured = self.allowed_database_tables.get(table)
        if configured is None:
            raise AuthorizationError("The database table is not authorized.")
        normalized_fields = tuple(field.strip() for field in fields)
        if any(field not in configured for field in normalized_fields):
            raise AuthorizationError("The database projection contains an unauthorized field.")
        if context_scope:
            allowed_scope = {field.lower() for field in context_scope}
            if any(field.lower() not in allowed_scope for field in normalized_fields):
                raise AuthorizationError("The database projection exceeds the task's allowed scope.")
        return normalized_fields
