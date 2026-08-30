"""Transformation: the handlers a verdict is dispatched to.

Nothing here decides anything. Each piece carries out one action against one
span, which is what lets the mask, the hash and the vault be reasoned about
separately from the rule that chose them.
"""

from .handlers import (
    DEFAULT_MASK_STYLE,
    MASK_CHARACTER,
    MASK_STYLES,
    Handler,
    HashHandler,
    MaskHandler,
    TokenizeHandler,
    default_handlers,
    normalize_for_hash,
)
from .router import AppliedTransform, Disposition, DispositionRouter
from .vault import TOKEN_PATTERN, Restoration, TokenVault


__all__ = [
    "DEFAULT_MASK_STYLE",
    "MASK_CHARACTER",
    "MASK_STYLES",
    "TOKEN_PATTERN",
    "AppliedTransform",
    "Disposition",
    "DispositionRouter",
    "Handler",
    "HashHandler",
    "MaskHandler",
    "Restoration",
    "TokenVault",
    "TokenizeHandler",
    "default_handlers",
    "normalize_for_hash",
]
