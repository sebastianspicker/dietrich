"""Typed assessment findings used by every interaction adapter."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dietrich.domain.models import ProtectionLayer


class CapabilityCode(StrEnum):
    """Operations an assessed document can support."""

    REMOVE_SOFT_PROTECTION = "remove_soft_protection"
    REMOVE_PDF_RESTRICTIONS = "remove_pdf_restrictions"
    RECOVER_OPEN_PASSWORD = "recover_open_password"
    EXPORT_PASSWORD_HASH = "export_password_hash"
    STRIP_SIGNATURES = "strip_signatures"
    CLEAR_VBA_VERIFIER = "clear_vba_verifier"


class BlockerCode(StrEnum):
    """Reasons a requested transformation cannot proceed locally."""

    IRM = "rights_management"
    UNKNOWN_FORMAT = "unknown_format"
    UNSUPPORTED_OPERATION = "unsupported_operation"


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
