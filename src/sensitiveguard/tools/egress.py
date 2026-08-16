"""Safe external LLM, HTTP and message egress tools."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from sensitiveguard.models import GuardStage
from sensitiveguard.runtime.error_model import SensitiveGuardError

from .base import SensitiveGuardTool


class SafeLLMCallTool(SensitiveGuardTool):
    name = "safe_llm_call"
    description = "Send only policy-minimized text to the host-configured external LLM."
    inputs = {
        "text": {"type": "string", "description": "Content to analyze."},
        "purpose": {"type": "string", "description": "Must match the host-authorized task purpose."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        client: Callable[[str], Any],
        destination: str = "external_llm",
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._client = client
        self.destination = destination

    def forward(self, text: str, purpose: str) -> dict[str, Any]:
        if purpose != self.context.purpose:
            return self.safe_block("The requested purpose does not match the host-authorized privacy context.")
        guarded = self.gateway.guard_text(
            text,
            self.context,
            GuardStage.TOOL_INPUT,
            destination=self.destination,
            recipient=self.context.recipient,
            tool_name=self.name,
            record_disclosure=True,
        )
        if not guarded.allowed:
            return self.result_payload(guarded)
        try:
            response = self._client(guarded.content)
        except Exception:
            return {"status": "FAILED", "reason": "The protected external LLM call failed."}
        observation = self.gateway.guard_payload(
            response,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=self.name,
            record_disclosure=False,
        )
        payload = self.result_payload(observation)
        payload["request_privacy_actions"] = list(guarded.decisions.actions)
        return payload


class SafeHTTPPostTool(SensitiveGuardTool):
    name = "safe_http_post"
    description = "POST a policy-approved payload only to a host-authorized HTTPS destination."
    inputs = {
        "url": {"type": "string", "description": "HTTPS URL; host must be allowlisted by the runtime."},
        "body": {"type": ["string", "object"], "description": "Payload to inspect before transmission."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        transport: Callable[[str, Any], Any],
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._transport = transport

    def forward(self, url: str, body: str | dict[str, Any]) -> dict[str, Any]:
        hostname = (urlsplit(url).hostname or "unknown").lower().rstrip(".")
        destination = f"http:{hostname}"
        guarded = self.gateway.guard_payload(
            {"url": url, "body": body},
            self.context,
            GuardStage.TOOL_INPUT,
            destination=destination,
            recipient=hostname,
            tool_name=self.name,
            record_disclosure=True,
        )
        if not guarded.allowed:
            return self.result_payload(guarded)
        safe_url = guarded.content["url"]
        safe_body = guarded.content["body"]
        try:
            self.gateway.authorization.authorize_url(safe_url)
        except SensitiveGuardError as error:
            return self.safe_block(error.public_message)
        try:
            response = self._transport(safe_url, safe_body)
        except Exception:
            return {"status": "FAILED", "reason": "The protected HTTP request failed."}
        observation = self.gateway.guard_payload(
            response,
            self.context,
            GuardStage.TOOL_OUTPUT,
            destination="agent_memory",
            tool_name=self.name,
            record_disclosure=False,
        )
        payload = self.result_payload(observation)
        payload["request_privacy_actions"] = list(guarded.decisions.actions)
        return payload


class SafeSendMessageTool(SensitiveGuardTool):
    name = "safe_send_message"
    description = "Send a policy-approved message to an exact host-allowlisted recipient."
    inputs = {
        "recipient": {"type": "string", "description": "Recipient authorized by the host."},
        "body": {"type": "string", "description": "Message body to inspect before sending."},
    }
    output_type = "object"
    handles_sensitive_input = True

    def __init__(
        self,
        *,
        gateway: Any,
        context: Any,
        sender: Callable[[str, str], Any],
        allowed_recipients: set[str] | frozenset[str],
    ) -> None:
        super().__init__(gateway=gateway, context=context)
        self._sender = sender
        self.allowed_recipients = frozenset(item.casefold() for item in allowed_recipients)

    def forward(self, recipient: str, body: str) -> dict[str, Any]:
        if recipient.casefold() not in self.allowed_recipients:
            return self.safe_block("The message recipient is not in the host allowlist.")
        domain = recipient.rsplit("@", 1)[-1].casefold() if "@" in recipient else "configured_recipient"
        guarded = self.gateway.guard_text(
            body,
            self.context,
            GuardStage.TOOL_INPUT,
            destination=f"message:{domain}",
            recipient=recipient,
            tool_name=self.name,
            record_disclosure=True,
        )
        if not guarded.allowed:
            return self.result_payload(guarded)
        try:
            self._sender(recipient, guarded.content)
        except Exception:
            return {"status": "FAILED", "reason": "The protected message send failed."}
        return {
            "status": "SENT",
            "recipient": domain,
            "privacy_actions": list(guarded.decisions.actions),
        }


# The architecture uses both names; keep a compatibility alias without exposing
# a second raw sender implementation.
class SafeSendEmailTool(SafeSendMessageTool):
    name = "safe_send_email"
    description = "Send a policy-approved email to an exact host-allowlisted recipient."
