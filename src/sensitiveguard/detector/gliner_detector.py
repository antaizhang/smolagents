"""Lazy, optional GLiNER adapter.

The module deliberately does not import GLiNER at import time and never asks a
model hub to download a model. Production callers should inject an initialized
model or a local-only model factory.
"""

from __future__ import annotations

import importlib
import inspect
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from sensitiveguard.detector.base import Detector, DetectorUnavailableError
from sensitiveguard.detector.composite import deduplicate_findings
from sensitiveguard.detector.labels import PII_LABELS, severity_for_label
from sensitiveguard.models import DetectionResult, Finding, Severity


ModelFactory = Callable[..., Any]


class GLiNERDetector(Detector):
    """Normalize a GLiNER-compatible model behind the Detector interface."""

    name = "gliner"

    def __init__(
        self,
        model: Any = None,
        *,
        model_path: str | Path | None = None,
        model_factory: ModelFactory | None = None,
        labels: Iterable[str] = PII_LABELS,
        threshold: float = 0.5,
        severity_overrides: Mapping[str, Severity] | None = None,
    ) -> None:
        if not 0 <= threshold <= 1:
            raise ValueError("GLiNER threshold must be between 0 and 1")
        self._model = model
        self.model_path = str(model_path) if model_path is not None else None
        self.model_factory = model_factory
        self.labels = tuple(labels)
        if not self.labels:
            raise ValueError("GLiNERDetector requires at least one label")
        self.threshold = float(threshold)
        self.severity_overrides = {
            str(label).upper(): (
                severity if isinstance(severity, Severity) else Severity(str(severity).strip().lower())
            )
            for label, severity in (severity_overrides or {}).items()
        }
        self._model_lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        return self._model is not None

    @property
    def model(self) -> Any:
        """Return the model, loading it locally on first access if configured."""

        return self._get_model()

    def _get_model(self) -> Any:
        if self._model is not None:
            return self._model
        with self._model_lock:
            if self._model is not None:
                return self._model
            if self.model_factory is not None:
                self._model = self._call_factory()
            elif self.model_path is not None:
                self._model = self._load_local_model()
            else:
                raise DetectorUnavailableError(
                    "GLiNER is optional. Inject an initialized model, a model_factory, or a local model_path."
                )
            if self._model is None:
                raise DetectorUnavailableError("The configured GLiNER model factory returned None")
        return self._model

    def _call_factory(self) -> Any:
        assert self.model_factory is not None
        try:
            signature = inspect.signature(self.model_factory)
        except (TypeError, ValueError):
            return self.model_factory(self.model_path)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in {parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD}
        ]
        if not positional:
            return self.model_factory()
        return self.model_factory(self.model_path)

    def _load_local_model(self) -> Any:
        try:
            module = importlib.import_module("gliner")
        except ImportError as error:
            raise DetectorUnavailableError(
                "GLiNER is not installed; install it separately or inject a compatible model"
            ) from error

        model_class = getattr(module, "GLiNER", None)
        if model_class is None or not hasattr(model_class, "from_pretrained"):
            raise DetectorUnavailableError("Installed gliner package does not expose GLiNER.from_pretrained")
        try:
            # Never retry without local_files_only: doing so could trigger a
            # network download, which is outside the runtime's safe default.
            return model_class.from_pretrained(self.model_path, local_files_only=True)
        except TypeError as error:
            raise DetectorUnavailableError(
                "This GLiNER version cannot guarantee local-only loading; inject a preloaded model instead"
            ) from error

    def detect(self, content: str, context: Any = None) -> DetectionResult:
        del context
        self.validate_content(content)
        if not content:
            return DetectionResult()

        model = self._get_model()
        predictor = getattr(model, "predict_entities", None)
        if not callable(predictor):
            raise TypeError("Injected GLiNER model must define predict_entities(text, labels, threshold=...)")
        raw_entities = predictor(content, list(self.labels), threshold=self.threshold)
        if raw_entities is None:
            return DetectionResult()

        findings: list[Finding] = []
        for entity in raw_entities:
            if not isinstance(entity, Mapping):
                raise TypeError("GLiNER predict_entities must return mappings")
            label = str(entity.get("label", "")).strip()
            if not label:
                raise ValueError("GLiNER entity is missing a label")
            try:
                start = int(entity["start"])
                end = int(entity["end"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("GLiNER entity must contain integer start and end offsets") from error
            if start < 0 or end <= start or end > len(content):
                raise ValueError(f"GLiNER returned invalid span ({start}, {end}) for content length {len(content)}")
            score = float(entity.get("score", 1.0))
            normalized_label = label.upper()
            findings.append(
                Finding(
                    label=label,
                    start=start,
                    end=end,
                    score=score,
                    severity=self.severity_overrides.get(normalized_label, severity_for_label(label)),
                    detector=self.name,
                    value=content[start:end],
                )
            )
        return DetectionResult(deduplicate_findings(findings))


__all__ = ["GLiNERDetector", "ModelFactory"]
