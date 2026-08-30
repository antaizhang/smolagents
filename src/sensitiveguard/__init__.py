"""A minimal phone-number detection Agent built on smolagents."""

from .llm import build_ollama_model
from .phone_agent import PhoneDetectionAgent, detect


__all__ = ["PhoneDetectionAgent", "build_ollama_model", "detect"]
