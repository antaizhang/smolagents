"""Built-in minimum policy set for the first SensitiveGuard runtime."""

from __future__ import annotations

from sensitiveguard.models import Action, GuardStage
from sensitiveguard.policy.rules import PolicyRule


def default_policy_rules() -> tuple[PolicyRule, ...]:
    """Return conservative rules that implement the three initial demos."""

    return (
        PolicyRule(
            policy_id="SG-INJECTION-001",
            action=Action.BLOCK,
            labels=("PROMPT_INJECTION",),
            reason="Prompt-injection instructions cannot authorize runtime actions",
            priority=10_000,
        ),
        PolicyRule(
            policy_id="SG-LLM-SECRET-001",
            action=Action.BLOCK,
            labels=("PASSWD", "API_KEY", "ACCESS_TOKEN", "JWT", "PRIVATE_KEY", "CLOUD_SECRET", "DATABASE_PASSWORD"),
            stages=(GuardStage.TOOL_INPUT,),
            destinations=("external_llm",),
            reason="Credentials and secrets cannot be disclosed to an external LLM",
            priority=900,
        ),
        PolicyRule(
            policy_id="SG-LLM-NAME-001",
            action=Action.PSEUDONYMIZE,
            labels=("NAME",),
            stages=(GuardStage.TOOL_INPUT,),
            destinations=("external_llm",),
            necessary=False,
            reason="A name is unnecessary for this external LLM task",
            priority=800,
        ),
        PolicyRule(
            policy_id="SG-LLM-ADDRESS-001",
            action=Action.GENERALIZE,
            labels=("ADDRESS",),
            stages=(GuardStage.TOOL_INPUT,),
            destinations=("external_llm",),
            necessary=False,
            reason="Only a generalized location may be used by the external LLM",
            priority=800,
        ),
        PolicyRule(
            policy_id="SG-LLM-FINANCIAL-001",
            action=Action.TOKENIZE,
            labels=("BANKACCOUNT", "FINACCOUNT"),
            stages=(GuardStage.TOOL_INPUT,),
            destinations=("external_llm",),
            necessary=False,
            reason="A one-way secure token replaces an unnecessary financial identifier",
            priority=800,
        ),
        PolicyRule(
            policy_id="SG-LLM-PII-001",
            action=Action.REDACT,
            labels=(
                "PASSPORTID",
                "IDCARD",
                "DRIVERID",
                "INSURANCEID",
                "HEALTHCARD",
                "RESIDENCEID",
                "MILITARYID",
                "TAXID",
                "VISAAUTH",
                "SOCIALID",
                "MOBILE",
                "EMAIL",
                "FAX",
                "TEL",
                "OUTPATIENTID",
                "PATIENTID",
            ),
            stages=(GuardStage.TOOL_INPUT,),
            destinations=("external_llm",),
            necessary=False,
            reason="The identifier is unnecessary for the external LLM task",
            priority=700,
        ),
    )


__all__ = ["default_policy_rules"]
