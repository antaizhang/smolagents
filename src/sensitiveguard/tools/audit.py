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
