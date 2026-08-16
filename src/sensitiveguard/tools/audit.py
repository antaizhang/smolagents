"""Trajectory audit report tool."""

from __future__ import annotations

from typing import Any

from .base import SensitiveGuardTool


class AuditPrivacyTrajectoryTool(SensitiveGuardTool):
    name = "audit_privacy_trajectory"
    description = "Return the current run's redacted privacy decisions, metrics and disclosure budget."
    inputs: dict[str, dict[str, str]] = {}
    output_type = "object"

    def forward(self) -> dict[str, Any]:
        report = self.gateway.audit_logger.report(self.context.run_id)
        report["disclosure"] = self.gateway.ledger.report(self.context.run_id)
        return report


class TraceDataLineageTool(SensitiveGuardTool):
    name = "trace_data_lineage"
    description = "Return the current run's payload-free data-lineage DAG and integrity status."
    inputs: dict[str, dict[str, str]] = {}
    output_type = "object"

    def forward(self) -> dict[str, Any]:
        tracker = getattr(self.gateway, "lineage_tracker", None)
        if tracker is None:
            return self.safe_block("Data lineage is not configured for this runtime.")
        return tracker.report(self.context).to_dict()
