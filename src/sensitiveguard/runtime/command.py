"""Structured, host-authorized command capabilities.

This module deliberately does not import :mod:`subprocess` and does not expose
an API accepting a shell command string.  It turns a small, structured request
into an immutable invocation for a host-injected executor.  The executor is
responsible for enforcing the resource and operating-system sandbox described
by :class:`AuthorizedCommand`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from sensitiveguard.crypto import constant_time_equals

from .authorization import AuthorizationPolicy
from .error_model import AuthorizationError, SensitiveGuardError, ToolExecutionError


_CAPABILITY_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_RULE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SHELL_META = frozenset("|&;<>`$\\*?[]{}()!")
_NETWORK_MARKERS = (
    "http://",
    "https://",
    "ftp://",
    "ssh://",
    "git://",
    "tcp://",
    "udp://",
)
_FORBIDDEN_OPTION_NAMES = frozenset(
    {
        "--command",
        "--config",
        "--config-env",
        "--connect",
        "--editor",
        "--eval",
        "--exec",
        "--extension",
        "--pager",
        "--plugin",
        "--pre",
        "--proxy",
        "--proxy-command",
        "--receive-pack",
        "--remote",
        "--upload",
        "--upload-pack",
        "-exec",
        "-execdir",
    }
)
_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "bash",
        "busybox",
        "curl",
        "dash",
        "doas",
        "env",
        "find",
        "fish",
        "ftp",
        "git",
        "ksh",
        "nc",
        "netcat",
        "node",
        "osascript",
        "perl",
        "php",
        "powershell",
        "pwsh",
        "ruby",
        "scp",
        "sftp",
        "sh",
        "socat",
        "ssh",
        "sudo",
        "telnet",
        "wget",
        "xargs",
        "zsh",
    }
)
_MAX_ARGUMENTS = 32
_MAX_TOKEN_CHARS = 4096
_MAX_TOTAL_CHARS = 16_384


class CommandError(SensitiveGuardError):
    """Base error whose public message never includes command material."""

    code = "COMMAND_FAILED"
    default_message = "The structured command could not be handled safely."


class CommandParseError(CommandError):
    code = "COMMAND_PARSE_FAILED"
    default_message = "The command request is not valid structured input."


class CommandAuthorizationError(AuthorizationError):
    code = "COMMAND_NOT_AUTHORIZED"
    default_message = "The command request is outside the authorized capability."


class CommandExecutorError(ToolExecutionError):
    code = "COMMAND_EXECUTION_FAILED"
    default_message = "The protected command executor failed."


class CommandPathAccess(str, Enum):
    READ = "read"
    WRITE = "write"


def _has_unsafe_characters(value: str) -> bool:
    if not value or len(value) > _MAX_TOKEN_CHARS:
        return True
    if any(character in _SHELL_META for character in value):
        return True
    if value.startswith("~"):
        return True
    if value.startswith("@"):
        return True
    if value.casefold().split("=", 1)[0] in _FORBIDDEN_OPTION_NAMES:
        return True
    if any(marker in value.casefold() for marker in _NETWORK_MARKERS):
        return True
    return any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value)


def _validate_token(value: object) -> str:
    if type(value) is not str or _has_unsafe_characters(value):
        raise CommandParseError()
    return value


@dataclass(frozen=True, slots=True)
class CommandArgumentRule:
    """One position in an exact command grammar.

    A capability has exactly one rule per accepted argument.  Optional flags
    should be represented as separate capabilities; this keeps the grammar
    deterministic and prevents surprising option interactions.
    """

    name: str
    kind: str
    literal: str | None = None
    choices: tuple[str, ...] = ()
    pattern: str | None = None
    path_access: CommandPathAccess | None = None
    must_exist: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _RULE_NAME.fullmatch(self.name):
            raise ValueError("Command argument rule names must be lowercase identifiers")
        if not isinstance(self.must_exist, bool):
            raise TypeError("Command path existence policy must be a boolean")
        kind = str(self.kind).strip().lower()
        if kind not in {"literal", "enum", "text", "path"}:
            raise ValueError("Command argument rules must be literal, enum, text or path")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "choices", tuple(self.choices))

        if kind == "literal":
            _validate_token(self.literal)
            if self.choices or self.pattern is not None or self.path_access is not None:
                raise ValueError("A literal command rule cannot define other validators")
        elif kind == "enum":
            if not self.choices:
                raise ValueError("An enum command rule requires at least one choice")
            for choice in self.choices:
                _validate_token(choice)
            if self.literal is not None or self.pattern is not None or self.path_access is not None:
                raise ValueError("An enum command rule cannot define other validators")
        elif kind == "text":
            if self.pattern is None:
                raise ValueError("A text command rule requires a full-match regular expression")
            try:
                re.compile(self.pattern)
            except re.error as error:
                raise ValueError("A text command rule has an invalid regular expression") from error
            if self.literal is not None or self.choices or self.path_access is not None:
                raise ValueError("A text command rule cannot define other validators")
        else:
            access = self.path_access
            if isinstance(access, str):
                try:
                    access = CommandPathAccess(access)
                except ValueError as error:
                    raise ValueError("A path command rule requires read or write access") from error
                object.__setattr__(self, "path_access", access)
            if not isinstance(access, CommandPathAccess):
                raise ValueError("A path command rule requires read or write access")
            if access is CommandPathAccess.READ and not self.must_exist:
                raise ValueError("Read path command rules must require an existing path")
            if self.literal is not None or self.choices or self.pattern is not None:
                raise ValueError("A path command rule cannot define other validators")

    @classmethod
    def fixed(cls, name: str, value: str) -> CommandArgumentRule:
        return cls(name=name, kind="literal", literal=value)

    @classmethod
    def one_of(cls, name: str, values: Iterable[str]) -> CommandArgumentRule:
        return cls(name=name, kind="enum", choices=tuple(values))

    @classmethod
    def safe_text(cls, name: str, pattern: str = r"[A-Za-z0-9][A-Za-z0-9._,:/@+=% -]{0,255}") -> CommandArgumentRule:
        return cls(name=name, kind="text", pattern=pattern)

    @classmethod
    def read_path(cls, name: str) -> CommandArgumentRule:
        return cls(name=name, kind="path", path_access=CommandPathAccess.READ, must_exist=True)

    @classmethod
    def write_path(cls, name: str, *, must_exist: bool = False) -> CommandArgumentRule:
        return cls(
            name=name,
            kind="path",
            path_access=CommandPathAccess.WRITE,
            must_exist=must_exist,
        )


@dataclass(frozen=True, slots=True)
class CommandCapability:
    """A host-defined executable and its complete accepted argument grammar."""

    name: str
    executable: Path | str
    argument_rules: tuple[CommandArgumentRule, ...] = ()
    allow_cwd: bool = False
    default_cwd: Path | str | None = None
    network_allowed: bool = False
    timeout_seconds: float = 10.0
    max_output_bytes: int = 256_000
    executable_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _CAPABILITY_NAME.fullmatch(self.name):
            raise ValueError("Command capability names must be lowercase identifiers")
        executable = Path(self.executable)
        if not executable.is_absolute():
            raise ValueError("Command capability executables must use absolute paths")
        executable_name = executable.name.casefold().removesuffix(".exe")
        if executable_name in _FORBIDDEN_EXECUTABLES or re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable_name):
            raise ValueError("Interpreters, shell launchers and network-capable executables are forbidden")
        object.__setattr__(self, "executable", executable)
        rules = tuple(self.argument_rules)
        if len(rules) > _MAX_ARGUMENTS or not all(isinstance(rule, CommandArgumentRule) for rule in rules):
            raise ValueError("Command capability argument grammar is invalid")
        object.__setattr__(self, "argument_rules", rules)
        if not isinstance(self.allow_cwd, bool) or not isinstance(self.network_allowed, bool):
            raise TypeError("Command capability flags must be booleans")
        if self.default_cwd is not None:
            default_cwd = Path(self.default_cwd)
            if not default_cwd.is_absolute():
                raise ValueError("A default command working directory must be absolute")
            object.__setattr__(self, "default_cwd", default_cwd)
        if self.network_allowed:
            raise ValueError("Safe command capabilities cannot enable network access")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("Command timeout must be numeric")
        if not math.isfinite(float(self.timeout_seconds)) or not 0 < float(self.timeout_seconds) <= 300:
            raise ValueError("Command timeout must be in the range (0, 300] seconds")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        if isinstance(self.max_output_bytes, bool) or not isinstance(self.max_output_bytes, int):
            raise TypeError("Command output limit must be an integer")
        if not 1 <= self.max_output_bytes <= 10_000_000:
            raise ValueError("Command output limit must be between 1 and 10,000,000 bytes")
        if self.executable_sha256 is not None:
            digest = str(self.executable_sha256).strip().lower()
            if not _SHA256.fullmatch(digest):
                raise ValueError("Executable SHA-256 must be a lowercase hexadecimal digest")
            object.__setattr__(self, "executable_sha256", digest)


@dataclass(frozen=True, slots=True)
class CommandRequest:
    capability: str
    argv: tuple[str, ...] = field(default=(), repr=False)
    cwd: str | None = field(default=None, repr=False)


class CommandParser:
    """Parse structured tokens only; shell command strings are never accepted."""

    def parse(self, capability: str, argv: Sequence[str], cwd: str | None = None) -> CommandRequest:
        if type(capability) is not str or not _CAPABILITY_NAME.fullmatch(capability):
            raise CommandParseError()
        if isinstance(argv, (str, bytes, bytearray)) or not isinstance(argv, (list, tuple)):
            raise CommandParseError()
        if len(argv) > _MAX_ARGUMENTS:
            raise CommandParseError()
        tokens = tuple(_validate_token(token) for token in argv)
        if sum(len(token) for token in tokens) > _MAX_TOTAL_CHARS:
            raise CommandParseError()
        normalized_cwd = None if cwd is None else _validate_token(cwd)
        return CommandRequest(capability=capability, argv=tokens, cwd=normalized_cwd)


@dataclass(frozen=True, slots=True)
class AuthorizedPath:
    argument_index: int
    path: Path = field(repr=False)
    access: CommandPathAccess


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class AuthorizedCommand:
    """An invocation that a sandboxed executor may consume.

    Executors must use ``full_argv`` directly, never join it into a string, must
    enforce ``network_allowed=False``, close inherited file descriptors, use a
    bounded stdout/stderr capture and honor the timeout/output limits.
    """

    capability: CommandCapability
    executable: Path = field(repr=False)
    argv: tuple[str, ...] = field(repr=False)
    cwd: Path | None = field(default=None, repr=False)
    authorized_paths: tuple[AuthorizedPath, ...] = field(default=(), repr=False)
    executable_identity: ExecutableIdentity | None = field(default=None, repr=False)
    network_allowed: bool = False

    @property
    def full_argv(self) -> tuple[str, ...]:
        return (str(self.executable), *self.argv)

    @property
    def data_argument_indices(self) -> tuple[int, ...]:
        return tuple(
            index for index, rule in enumerate(self.capability.argument_rules) if rule.kind in {"text", "path"}
        )


@dataclass(frozen=True, slots=True)
class CommandExecutionResult:
    exit_code: int
    stdout: bytes | str = field(default=b"", repr=False)
    stderr: bytes | str = field(default=b"", repr=False)
    timed_out: bool = False
    output_overflow: bool = False
    duration_ms: float = 0.0

    def __post_init__(self) -> None:
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise TypeError("Command execution exit_code must be an integer")
        if not isinstance(self.stdout, (bytes, str)) or not isinstance(self.stderr, (bytes, str)):
            raise TypeError("Command execution output must be bytes or strings")
        if not isinstance(self.timed_out, bool) or not isinstance(self.output_overflow, bool):
            raise TypeError("Command execution flags must be booleans")
        if isinstance(self.duration_ms, bool) or not isinstance(self.duration_ms, (int, float)):
            raise TypeError("Command execution duration must be numeric")
        if not math.isfinite(float(self.duration_ms)) or float(self.duration_ms) < 0:
            raise ValueError("Command execution duration must be non-negative")
        object.__setattr__(self, "duration_ms", float(self.duration_ms))


@runtime_checkable
class CommandExecutor(Protocol):
    def execute(self, command: AuthorizedCommand) -> CommandExecutionResult:
        """Execute one already-authorized command inside a networkless sandbox."""


class CommandAuthorizer:
    """Resolve an exact capability grammar against host filesystem policy."""

    def __init__(
        self,
        capabilities: Mapping[str, CommandCapability] | Iterable[CommandCapability],
        authorization: AuthorizationPolicy,
    ) -> None:
        if not isinstance(authorization, AuthorizationPolicy):
            raise TypeError("CommandAuthorizer requires an AuthorizationPolicy")
        if isinstance(capabilities, Mapping):
            values = tuple(capabilities.values())
        else:
            values = tuple(capabilities)
        if not all(isinstance(capability, CommandCapability) for capability in values):
            raise TypeError("Command capabilities must contain only CommandCapability objects")
        if isinstance(capabilities, Mapping) and any(
            key != capability.name for key, capability in capabilities.items()
        ):
            raise ValueError("Command capability mapping keys must match capability names")
        indexed = {capability.name: capability for capability in values}
        if len(indexed) != len(values):
            raise ValueError("Command capability names must be unique")
        self.capabilities = MappingProxyType(indexed)
        self.authorization = authorization

    def authorize(self, request: CommandRequest) -> AuthorizedCommand:
        if not isinstance(request, CommandRequest):
            raise TypeError("CommandAuthorizer expects a CommandRequest")
        capability = self.capabilities.get(request.capability)
        if capability is None:
            raise CommandAuthorizationError()
        if capability.network_allowed:
            raise CommandAuthorizationError()
        if len(request.argv) != len(capability.argument_rules):
            raise CommandAuthorizationError()

        executable, identity = self._authorize_executable(capability)
        cwd = self._authorize_cwd(capability, request.cwd)
        normalized: list[str] = []
        authorized_paths: list[AuthorizedPath] = []
        for index, (token, rule) in enumerate(zip(request.argv, capability.argument_rules)):
            if rule.kind == "literal":
                if not constant_time_equals(token, rule.literal or ""):
                    raise CommandAuthorizationError()
                normalized.append(token)
            elif rule.kind == "enum":
                if not any(constant_time_equals(token, choice) for choice in rule.choices):
                    raise CommandAuthorizationError()
                normalized.append(token)
            elif rule.kind == "text":
                if rule.pattern is None or re.fullmatch(rule.pattern, token) is None:
                    raise CommandAuthorizationError()
                normalized.append(token)
            else:
                path = Path(token)
                if not path.is_absolute():
                    if cwd is None:
                        raise CommandAuthorizationError()
                    path = cwd / path
                access = rule.path_access
                assert isinstance(access, CommandPathAccess)
                try:
                    resolved = self.authorization.authorize_path(
                        path,
                        write=access is CommandPathAccess.WRITE,
                        must_exist=rule.must_exist,
                    )
                except AuthorizationError:
                    raise CommandAuthorizationError() from None
                if access is CommandPathAccess.WRITE and not rule.must_exist and resolved.exists():
                    raise CommandAuthorizationError()
                normalized.append(str(resolved))
                authorized_paths.append(AuthorizedPath(index, resolved, access))

        return AuthorizedCommand(
            capability=capability,
            executable=executable,
            argv=tuple(normalized),
            cwd=cwd,
            authorized_paths=tuple(authorized_paths),
            executable_identity=identity,
            network_allowed=False,
        )

    def _authorize_cwd(self, capability: CommandCapability, requested: str | None) -> Path | None:
        if requested is not None and not capability.allow_cwd:
            raise CommandAuthorizationError()
        candidate: Path | None = Path(requested) if requested is not None else capability.default_cwd
        if candidate is None:
            return None
        try:
            resolved = self.authorization.authorize_path(candidate, must_exist=True)
        except AuthorizationError:
            raise CommandAuthorizationError() from None
        if not resolved.is_dir():
            raise CommandAuthorizationError()
        return resolved

    @staticmethod
    def _authorize_executable(
        capability: CommandCapability,
    ) -> tuple[Path, ExecutableIdentity]:
        configured = capability.executable
        assert isinstance(configured, Path)
        try:
            if configured.is_symlink():
                raise CommandAuthorizationError()
            resolved = configured.resolve(strict=True)
            if resolved != configured or not resolved.is_file() or not os.access(resolved, os.X_OK):
                raise CommandAuthorizationError()
            file_stat = resolved.stat()
        except (OSError, RuntimeError):
            raise CommandAuthorizationError() from None
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CommandAuthorizationError()
        if capability.executable_sha256 is not None:
            digest = hashlib.sha256()
            try:
                with resolved.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError:
                raise CommandAuthorizationError() from None
            if not hmac.compare_digest(digest.hexdigest(), capability.executable_sha256):
                raise CommandAuthorizationError()
        identity = ExecutableIdentity(
            device=file_stat.st_dev,
            inode=file_stat.st_ino,
            size=file_stat.st_size,
            modified_ns=file_stat.st_mtime_ns,
        )
        return resolved, identity


def fingerprint_command(key: bytes, command: AuthorizedCommand) -> str:
    """Return a keyed fingerprint without serializing raw argv into audit."""

    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("Command fingerprint key must contain at least 16 bytes")
    payload = json.dumps(
        {
            "capability": command.capability.name,
            "argv": command.argv,
            "cwd": str(command.cwd) if command.cwd is not None else None,
            "executable_identity": (
                None
                if command.executable_identity is None
                else {
                    "device": command.executable_identity.device,
                    "inode": command.executable_identity.inode,
                    "size": command.executable_identity.size,
                    "modified_ns": command.executable_identity.modified_ns,
                }
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


__all__ = [
    "AuthorizedCommand",
    "AuthorizedPath",
    "CommandArgumentRule",
    "CommandAuthorizationError",
    "CommandAuthorizer",
    "CommandCapability",
    "CommandError",
    "CommandExecutionResult",
    "CommandExecutor",
    "CommandExecutorError",
    "CommandParseError",
    "CommandParser",
    "CommandPathAccess",
    "CommandRequest",
    "ExecutableIdentity",
    "fingerprint_command",
]
