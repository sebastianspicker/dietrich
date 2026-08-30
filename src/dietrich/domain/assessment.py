"""Typed assessment findings used by every interaction adapter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, auto

from dietrich.domain.models import ProtectionLayer


class CapabilityCode(StrEnum):
    """Operations an assessed document can support."""

    REMOVE_SOFT_PROTECTION = auto()
    REMOVE_PDF_RESTRICTIONS = auto()
    RECOVER_OPEN_PASSWORD = auto()
    EXPORT_PASSWORD_HASH = auto()
    STRIP_SIGNATURES = auto()
    CLEAR_VBA_VERIFIER = auto()


class BlockerCode(StrEnum):
    """Reasons a requested transformation cannot proceed locally."""

    IRM = "rights_management"
    UNKNOWN_FORMAT = auto()
    UNSUPPORTED_OPERATION = auto()


@dataclass(frozen=True)
class Capability:
    """One supported operation and the protection layer it addresses."""

    code: CapabilityCode
    layer: ProtectionLayer
    detail: str


@dataclass(frozen=True)
class Blocker:
    """One assessed condition that prevents local transformation."""

    code: BlockerCode
    detail: str


__all__ = ["Blocker", "BlockerCode", "Capability", "CapabilityCode"]
