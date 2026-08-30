"""SensitiveGuard: detection, policy, routing and privilege separation.

The layers are deliberately separate, and the seams are the design:

``facts`` / ``detection``
    What is in the content. Detectors emit spans, labels and confidences, and
    nothing else. A cascade runs cheap detectors first and escalates only the
    spans that are still ambiguous, so a model call stays rare and short.
``policy``
    What to do about a fact. A versioned, diffable, self-testing rule file
    resolves ``label x confidence x purpose x destination x caller role`` into
    an action, and prints the path it took to get there. No model participates.
``transform``
    Carrying a verdict out. One handler per action, plus the vault that makes
    tokenisation reversible when — and only when — a rule says the response
    should be restored.
``agents``
    Who may see what. The component that reads untrusted content holds no
    authority, and the component that holds authority never reads the content.
``review``
    Checking the output both ways: the mask has to hold, and it has to leave
    enough behind for the task to still work.
"""

from .agents import PrivilegedGuardAgent, QuarantinedDetectorAgent
from .detection import (
    API_KEY,
    BANK_CARD,
    EMAIL,
    ID_CARD,
    PHONE,
    AmbiguousNumberDetector,
    CapabilityRouter,
    CascadeDetector,
    CascadeTier,
    DetectionReport,
    Detector,
    EscalationDetector,
    PhoneAgentDetector,
    RegexDetector,
)
from .facts import ContentKind, Finding, Span
from .llm import build_ollama_model
from .phone_agent import PhoneDetectionAgent, detect
from .pipeline import GuardResult, SensitiveGuard
from .policy import (
    Action,
    Condition,
    Decision,
    Policy,
    PolicyEngine,
    PolicyError,
    RequestContext,
    Rule,
    default_policy,
    diff_policies,
    load_policy,
)
from .quarantine import Quarantine, quarantine
from .review import Leak, OutputReviewer, ReviewReport
from .transform import Disposition, DispositionRouter, Restoration, TokenVault


__all__ = [
    "API_KEY",
    "BANK_CARD",
    "EMAIL",
    "ID_CARD",
    "PHONE",
    "Action",
    "AmbiguousNumberDetector",
    "CapabilityRouter",
    "CascadeDetector",
    "CascadeTier",
    "Condition",
    "ContentKind",
    "Decision",
    "DetectionReport",
    "Detector",
    "Disposition",
    "DispositionRouter",
    "EscalationDetector",
    "Finding",
    "GuardResult",
    "Leak",
    "OutputReviewer",
    "PhoneAgentDetector",
    "PhoneDetectionAgent",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PrivilegedGuardAgent",
    "Quarantine",
    "QuarantinedDetectorAgent",
    "RegexDetector",
    "RequestContext",
    "Restoration",
    "ReviewReport",
    "Rule",
    "SensitiveGuard",
    "Span",
    "TokenVault",
    "build_ollama_model",
    "default_policy",
    "detect",
    "diff_policies",
    "load_policy",
    "quarantine",
]
