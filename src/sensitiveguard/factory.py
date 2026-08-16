"""High-level assembly helpers for a production-hosted SensitiveGuard runtime."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sensitiveguard.agent import SensitiveToolCallingAgent
from sensitiveguard.audit import AuditLogger
from sensitiveguard.detector import (
    CompositeDetector,
    GLiNERDetector,
    InjectionDetector,
    RegexDetector,
    SecretDetector,
)
from sensitiveguard.policy import PolicyEngine, load_policy_config
from sensitiveguard.privacy import DisclosureLedger, PrivacyContext
from sensitiveguard.runtime import ApprovalStore, AuthorizationPolicy, SafeToolGateway
from sensitiveguard.tools import (
    AuditPrivacyTrajectoryTool,
    DetectSensitiveDataTool,
    EvaluateDataPolicyTool,
    FilePrivacyService,
    FinalAnswerGuardTool,
    MaskTextTool,
    PseudonymizeTextTool,
    RedactTextTool,
    RemediateSensitiveFileTool,
    SafeHTTPPostTool,
    SafeLLMCallTool,
    SafeQueryDatabaseTool,
    SafeReadFileTool,
    SafeRetrieveRAGTool,
    SafeSendMessageTool,
    SanitizeFileTool,
    SanitizeTextTool,
    ScanDirectoryTool,
    ScanFileTool,
    SensitiveGuardTool,
    TokenizeSensitiveDataTool,
    VerifySanitizedFileTool,
)
from sensitiveguard.transform import TransformationEngine


@dataclass(slots=True)
class SensitiveGuardRuntime:
    context: PrivacyContext
    detector: Any
    policy_engine: PolicyEngine
    transformer: TransformationEngine
    ledger: DisclosureLedger
    audit_logger: AuditLogger
    authorization: AuthorizationPolicy
    approval_store: ApprovalStore
    gateway: SafeToolGateway

    @classmethod
    def create(
        cls,
        context: PrivacyContext,
        *,
        gliner_model: Any | None = None,
        gliner_model_path: str | Path | None = None,
        gliner_model_factory: Callable[..., Any] | None = None,
        gliner_threshold: float = 0.5,
        allowed_roots: Iterable[str | Path] = (),
        allowed_http_hosts: Iterable[str] = (),
        allow_http: bool = False,
        allow_private_networks: bool = False,
        allowed_database_tables: dict[str, Iterable[str]] | None = None,
        known_external_destinations: Iterable[str] | None = None,
        policy_source: Any | None = None,
        default_privacy_budget: float = 100.0,
        destination_budgets: dict[str, float] | None = None,
        audit_jsonl_path: str | Path | None = None,
        approval_callback: Callable[[Any, PrivacyContext, str], bool] | None = None,
        approval_ttl_seconds: float = 300.0,
    ) -> SensitiveGuardRuntime:
        if not isinstance(context, PrivacyContext):
            raise TypeError("SensitiveGuardRuntime.create expects a PrivacyContext")
        detector_chain: list[Any] = [RegexDetector(), SecretDetector(), InjectionDetector()]
        if gliner_model is not None or gliner_model_path is not None or gliner_model_factory is not None:
            detector_chain.insert(
                0,
                GLiNERDetector(
                    model=gliner_model,
                    model_path=gliner_model_path,
                    model_factory=gliner_model_factory,
                    threshold=gliner_threshold,
                ),
            )
        detector = CompositeDetector(detector_chain)

        http_hosts = frozenset(str(host).lower().rstrip(".") for host in allowed_http_hosts)
        destinations = tuple(known_external_destinations or ())
        if not destinations:
            destinations = (
                "external_llm",
                "managed_agent",
                "requester",
                *(f"http:{host}" for host in sorted(http_hosts)),
            )
        if policy_source is None:
            policy_engine = PolicyEngine(known_external_destinations=destinations)
        else:
            policy_config = load_policy_config(policy_source)
            policy_engine = PolicyEngine(
                policy_config.rules,
                known_external_destinations=destinations,
                policy_version=policy_config.version,
            )
        transformer = TransformationEngine()
        ledger = DisclosureLedger(
            default_budget=default_privacy_budget,
            destination_budgets=destination_budgets,
        )
        audit_logger = AuditLogger(audit_jsonl_path, default_run_id=context.run_id, fail_closed=True)
        authorization = AuthorizationPolicy(
            allowed_roots=tuple(allowed_roots),
            allowed_http_hosts=http_hosts,
            allow_http=allow_http,
            allow_private_networks=allow_private_networks,
            allowed_database_tables={
                table: frozenset(fields) for table, fields in (allowed_database_tables or {}).items()
            },
        )
        approval_store = ApprovalStore(ttl_seconds=approval_ttl_seconds)
        gateway = SafeToolGateway(
            detector=detector,
            policy_engine=policy_engine,
            transformer=transformer,
            ledger=ledger,
            audit_logger=audit_logger,
            authorization=authorization,
            approval_callback=approval_callback or approval_store,
        )
        return cls(
            context=context,
            detector=detector,
            policy_engine=policy_engine,
            transformer=transformer,
            ledger=ledger,
            audit_logger=audit_logger,
            authorization=authorization,
            approval_store=approval_store,
            gateway=gateway,
        )

    def build_tools(
        self,
        *,
        external_llm_client: Callable[[str], Any] | None = None,
        http_transport: Callable[[str, Any], Any] | None = None,
        message_sender: Callable[[str, str], Any] | None = None,
        allowed_message_recipients: Iterable[str] = (),
        database_executor: Callable[[str, tuple[str, ...], dict[str, Any]], Any] | None = None,
        rag_retriever: Callable[[str, int, tuple[str, ...]], Any] | None = None,
        max_file_bytes: int = 5_000_000,
        max_files: int = 1_000,
    ) -> list[SensitiveGuardTool]:
        tools: list[SensitiveGuardTool] = [
            DetectSensitiveDataTool(detector=self.detector, context=self.context),
            EvaluateDataPolicyTool(gateway=self.gateway, context=self.context),
            SanitizeTextTool(gateway=self.gateway, context=self.context),
            MaskTextTool(detector=self.detector, transformer=self.transformer, context=self.context),
            RedactTextTool(detector=self.detector, transformer=self.transformer, context=self.context),
            PseudonymizeTextTool(detector=self.detector, transformer=self.transformer, context=self.context),
            TokenizeSensitiveDataTool(detector=self.detector, transformer=self.transformer, context=self.context),
            AuditPrivacyTrajectoryTool(gateway=self.gateway, context=self.context),
            FinalAnswerGuardTool(gateway=self.gateway, context=self.context),
        ]
        if self.authorization.allowed_roots:
            file_service = FilePrivacyService(
                gateway=self.gateway,
                context=self.context,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
            )
            tools.extend(
                [
                    ScanFileTool(service=file_service),
                    ScanDirectoryTool(service=file_service),
                    SafeReadFileTool(service=file_service),
                    SanitizeFileTool(service=file_service),
                    RemediateSensitiveFileTool(service=file_service),
                    VerifySanitizedFileTool(service=file_service),
                ]
            )
        if external_llm_client is not None:
            tools.append(
                SafeLLMCallTool(
                    gateway=self.gateway,
                    context=self.context,
                    client=external_llm_client,
                )
            )
        if http_transport is not None:
            tools.append(SafeHTTPPostTool(gateway=self.gateway, context=self.context, transport=http_transport))
        if message_sender is not None:
            tools.append(
                SafeSendMessageTool(
                    gateway=self.gateway,
                    context=self.context,
                    sender=message_sender,
                    allowed_recipients=set(allowed_message_recipients),
                )
            )
        if database_executor is not None:
            tools.append(
                SafeQueryDatabaseTool(
                    gateway=self.gateway,
                    context=self.context,
                    query_executor=database_executor,
                )
            )
        if rag_retriever is not None:
            tools.append(
                SafeRetrieveRAGTool(
                    gateway=self.gateway,
                    context=self.context,
                    retriever=rag_retriever,
                )
            )
        return tools

    def create_agent(
        self,
        model: Any,
        *,
        tools: list[SensitiveGuardTool] | None = None,
        model_destination: str = "external_llm",
        **agent_kwargs: Any,
    ) -> SensitiveToolCallingAgent:
        return SensitiveToolCallingAgent(
            model=model,
            tools=tools if tools is not None else self.build_tools(),
            gateway=self.gateway,
            privacy_context=self.context,
            model_destination=model_destination,
            **agent_kwargs,
        )


def create_sensitive_agent(
    model: Any,
    context: PrivacyContext,
    *,
    runtime_kwargs: dict[str, Any] | None = None,
    tool_kwargs: dict[str, Any] | None = None,
    agent_kwargs: dict[str, Any] | None = None,
) -> SensitiveToolCallingAgent:
    runtime = SensitiveGuardRuntime.create(context, **(runtime_kwargs or {}))
    tools = runtime.build_tools(**(tool_kwargs or {}))
    return runtime.create_agent(model, tools=tools, **(agent_kwargs or {}))
