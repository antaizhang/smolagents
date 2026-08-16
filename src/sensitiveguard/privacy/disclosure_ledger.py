"""Thread-safe trajectory-level disclosure budgets."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from threading import RLock

from sensitiveguard.models import Action, DecisionSet, PolicyDecision, Severity


class DisclosureLedgerError(RuntimeError):
    """Base class for ledger failures."""


class PrivacyBudgetExceeded(DisclosureLedgerError):
    """Raised when a caller requests exception-based budget enforcement."""

    def __init__(self, reservation: "LedgerReservation") -> None:
        self.reservation = reservation
        super().__init__(reservation.reason or "Privacy budget exceeded")


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    reservation_id: str
    run_id: str
    destination: str
    label: str
    action: Action
    representation: str
    risk: float
    policy_id: str
    entity_fingerprint: str | None
    timestamp: float

    def to_dict(self) -> dict[str, object]:
        return {
            "reservation_id": self.reservation_id,
            "run_id": self.run_id,
            "destination": self.destination,
            "label": self.label,
            "action": self.action.value,
            "representation": self.representation,
            "risk": self.risk,
            "policy_id": self.policy_id,
            "entity_fingerprint": self.entity_fingerprint,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class LedgerReservation:
    allowed: bool
    run_id: str
    destination: str
    requested_risk: float
    cumulative_risk: float
    budget: float
    remaining_budget: float
    entries: tuple[LedgerEntry, ...] = ()
    reason: str | None = None

    def __bool__(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "run_id": self.run_id,
            "destination": self.destination,
            "requested_risk": self.requested_risk,
            "cumulative_risk": self.cumulative_risk,
            "budget": self.budget,
            "remaining_budget": self.remaining_budget,
            "entries": [entry.to_dict() for entry in self.entries],
            "reason": self.reason,
        }


_SEVERITY_RISK = {
    Severity.LOW: 5.0,
    Severity.MEDIUM: 15.0,
    Severity.HIGH: 30.0,
    Severity.CRITICAL: 50.0,
}
_EXPOSURE_FACTOR = {
    Action.ALLOW: 1.0,
    Action.MASK: 0.40,
    Action.GENERALIZE: 0.25,
    Action.PSEUDONYMIZE: 0.15,
    Action.TOKENIZE: 0.10,
    Action.REDACT: 0.0,
    Action.BLOCK: 0.0,
    Action.REQUIRE_APPROVAL: 0.0,
}


class DisclosureLedger:
    """Track disclosure risk independently for each run and destination.

    ``reserve`` performs the budget check and state mutation while holding one
    lock, so two concurrent disclosures cannot both spend the same remainder.
    ``preflight`` is intentionally advisory; callers must still use ``reserve``
    immediately before egress.
    """

    def __init__(
        self,
        default_budget: float = 100.0,
        *,
        destination_budgets: Mapping[str, float] | None = None,
        fingerprint_key: bytes | None = None,
    ) -> None:
        self._validate_budget(default_budget)
        self.default_budget = float(default_budget)
        self._destination_budgets = {
            destination: self._validated_budget(budget) for destination, budget in (destination_budgets or {}).items()
        }
        key = fingerprint_key if fingerprint_key is not None else secrets.token_bytes(32)
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("fingerprint_key must contain at least 16 bytes")
        self._fingerprint_key = key
        self._scope_budgets: dict[tuple[str, str], float] = {}
        self._cumulative: dict[tuple[str, str], float] = {}
        self._entries: dict[tuple[str, str], list[LedgerEntry]] = {}
        self._reservation_sequences: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    def set_budget(self, run_id: str, destination: str, budget: float) -> None:
        scope = self._scope(run_id, destination)
        validated = self._validated_budget(budget)
        with self._lock:
            already_reserved = self._cumulative.get(scope, 0.0)
            if validated < already_reserved:
                raise ValueError("budget cannot be lower than risk already reserved")
            self._scope_budgets[scope] = validated

    def set_destination_budget(self, destination: str, budget: float) -> None:
        if not destination:
            raise ValueError("destination must not be empty")
        validated = self._validated_budget(budget)
        with self._lock:
            over_budget_runs = [
                run_id
                for (run_id, scope_destination), cumulative in self._cumulative.items()
                if scope_destination == destination
                and (run_id, scope_destination) not in self._scope_budgets
                and cumulative > validated
            ]
            if over_budget_runs:
                raise ValueError("budget cannot be lower than risk already reserved for this destination")
            self._destination_budgets[destination] = validated

    def budget_for(self, run_id: str, destination: str) -> float:
        scope = self._scope(run_id, destination)
        with self._lock:
            return self._budget_for_scope(scope)

    def preflight(
        self,
        run_id: str,
        destination: str,
        decisions: DecisionSet | Iterable[PolicyDecision],
    ) -> LedgerReservation:
        policy_decisions = self._materialize(decisions)
        scope = self._scope(run_id, destination)
        with self._lock:
            return self._evaluate(scope, policy_decisions, create_entries=False)

    def can_reserve(
        self,
        run_id: str,
        destination: str,
        decisions: DecisionSet | Iterable[PolicyDecision],
    ) -> bool:
        return bool(self.preflight(run_id, destination, decisions))

    def reserve(
        self,
        run_id: str,
        destination: str,
        decisions: DecisionSet | Iterable[PolicyDecision],
        *,
        raise_on_exceeded: bool = False,
    ) -> LedgerReservation:
        policy_decisions = self._materialize(decisions)
        scope = self._scope(run_id, destination)
        with self._lock:
            reservation = self._evaluate(scope, policy_decisions, create_entries=True)
            if reservation.allowed:
                self._cumulative[scope] = reservation.cumulative_risk
                self._entries.setdefault(scope, []).extend(reservation.entries)
                self._reservation_sequences[scope] = self._reservation_sequences.get(scope, 0) + 1
            elif raise_on_exceeded:
                raise PrivacyBudgetExceeded(reservation)
            return reservation

    def cumulative_risk(self, run_id: str, destination: str) -> float:
        scope = self._scope(run_id, destination)
        with self._lock:
            return self._cumulative.get(scope, 0.0)

    def remaining_budget(self, run_id: str, destination: str) -> float:
        scope = self._scope(run_id, destination)
        with self._lock:
            return max(0.0, self._budget_for_scope(scope) - self._cumulative.get(scope, 0.0))

    def entries(self, run_id: str | None = None, destination: str | None = None) -> tuple[LedgerEntry, ...]:
        if run_id is None and destination is not None:
            raise ValueError("destination filtering requires run_id")
        with self._lock:
            if run_id is not None and destination is not None:
                return tuple(self._entries.get((run_id, destination), ()))
            if run_id is not None:
                return tuple(
                    entry
                    for (entry_run_id, _), entries in self._entries.items()
                    if entry_run_id == run_id
                    for entry in entries
                )
            return tuple(entry for entries in self._entries.values() for entry in entries)

    def report(self, run_id: str, destination: str | None = None) -> dict[str, object]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        with self._lock:
            destinations = (
                [destination]
                if destination is not None
                else sorted(
                    {scope_destination for scope_run, scope_destination in self._entries if scope_run == run_id}
                )
            )
            scopes = []
            for scope_destination in destinations:
                scope = (run_id, scope_destination)
                budget = self._budget_for_scope(scope)
                cumulative = self._cumulative.get(scope, 0.0)
                scopes.append(
                    {
                        "destination": scope_destination,
                        "budget": budget,
                        "cumulative_risk": cumulative,
                        "remaining_budget": max(0.0, budget - cumulative),
                        "entries": [entry.to_dict() for entry in self._entries.get(scope, ())],
                    }
                )
            return {"run_id": run_id, "destinations": scopes}

    def clear_run(self, run_id: str) -> None:
        with self._lock:
            scopes = {scope for scope in self._all_scopes() if scope[0] == run_id}
            for scope in scopes:
                self._scope_budgets.pop(scope, None)
                self._cumulative.pop(scope, None)
                self._entries.pop(scope, None)
                self._reservation_sequences.pop(scope, None)

    def _evaluate(
        self,
        scope: tuple[str, str],
        decisions: tuple[PolicyDecision, ...],
        *,
        create_entries: bool,
    ) -> LedgerReservation:
        run_id, destination = scope
        budget = self._budget_for_scope(scope)
        current = self._cumulative.get(scope, 0.0)

        policy_block = next(
            (decision for decision in decisions if decision.action in {Action.BLOCK, Action.REQUIRE_APPROVAL}),
            None,
        )
        if policy_block is not None:
            return LedgerReservation(
                allowed=False,
                run_id=run_id,
                destination=destination,
                requested_risk=0.0,
                cumulative_risk=current,
                budget=budget,
                remaining_budget=max(0.0, budget - current),
                reason=f"Policy {policy_block.policy_id} requires {policy_block.action.value}",
            )

        risks = tuple(self._decision_risk(decision) for decision in decisions)
        requested = math.fsum(risks)
        projected = current + requested
        if projected > budget:
            return LedgerReservation(
                allowed=False,
                run_id=run_id,
                destination=destination,
                requested_risk=requested,
                cumulative_risk=current,
                budget=budget,
                remaining_budget=max(0.0, budget - current),
                reason=(f"Privacy budget exceeded for destination {destination}: {projected:.4f} > {budget:.4f}"),
            )

        entries: tuple[LedgerEntry, ...] = ()
        if create_entries:
            sequence = self._reservation_sequences.get(scope, 0) + 1
            reservation_id = f"reservation-{sequence:06d}"
            timestamp = time.time()
            entries = tuple(
                LedgerEntry(
                    reservation_id=reservation_id,
                    run_id=run_id,
                    destination=destination,
                    label=decision.finding.label,
                    action=decision.action,
                    representation=decision.action.value.lower(),
                    risk=risk,
                    policy_id=decision.policy_id,
                    entity_fingerprint=self._fingerprint(decision, run_id, destination),
                    timestamp=timestamp,
                )
                for decision, risk in zip(decisions, risks)
            )

        return LedgerReservation(
            allowed=True,
            run_id=run_id,
            destination=destination,
            requested_risk=requested,
            cumulative_risk=projected,
            budget=budget,
            remaining_budget=max(0.0, budget - projected),
            entries=entries,
        )

    @staticmethod
    def _materialize(decisions: DecisionSet | Iterable[PolicyDecision]) -> tuple[PolicyDecision, ...]:
        values = decisions.decisions if isinstance(decisions, DecisionSet) else tuple(decisions)
        if not all(isinstance(decision, PolicyDecision) for decision in values):
            raise TypeError("decisions must contain only PolicyDecision objects")
        return tuple(values)

    @staticmethod
    def _decision_risk(decision: PolicyDecision) -> float:
        if decision.action in {Action.BLOCK, Action.REDACT, Action.REQUIRE_APPROVAL}:
            return 0.0
        if decision.risk is not None:
            # The policy score describes the raw entity/context risk. Charge
            # the representation that actually crosses the boundary so that
            # raw > masked > generalized > pseudonymized > tokenized.
            return max(0.0, float(decision.risk.score)) * _EXPOSURE_FACTOR[decision.action]
        return _SEVERITY_RISK[decision.severity] * _EXPOSURE_FACTOR[decision.action]

    def _fingerprint(self, decision: PolicyDecision, run_id: str, destination: str) -> str | None:
        value = decision.finding.value
        if not value:
            return None
        payload = (
            f"{len(run_id)}:{run_id}{len(destination)}:{destination}"
            f"{len(decision.finding.label)}:{decision.finding.label}{len(value)}:{value}"
        ).encode()
        return hmac.new(self._fingerprint_key, payload, hashlib.sha256).hexdigest()

    def _budget_for_scope(self, scope: tuple[str, str]) -> float:
        return self._scope_budgets.get(
            scope,
            self._destination_budgets.get(scope[1], self.default_budget),
        )

    def _all_scopes(self) -> set[tuple[str, str]]:
        return set(self._scope_budgets) | set(self._cumulative) | set(self._entries) | set(self._reservation_sequences)

    @staticmethod
    def _scope(run_id: str, destination: str) -> tuple[str, str]:
        if not run_id:
            raise ValueError("run_id must not be empty")
        if not destination:
            raise ValueError("destination must not be empty")
        return run_id, destination

    @staticmethod
    def _validate_budget(budget: float) -> None:
        if isinstance(budget, bool) or not isinstance(budget, (int, float)):
            raise TypeError("budget must be a number")
        if not math.isfinite(float(budget)) or float(budget) < 0:
            raise ValueError("budget must be finite and non-negative")

    @classmethod
    def _validated_budget(cls, budget: float) -> float:
        cls._validate_budget(budget)
        return float(budget)


__all__ = [
    "DisclosureLedger",
    "DisclosureLedgerError",
    "LedgerEntry",
    "LedgerReservation",
    "PrivacyBudgetExceeded",
]
