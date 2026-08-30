"""Core document, operation, and result models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dietrich.domain.assessment import Blocker, Capability


class DocumentFormat(StrEnum):
    EXCEL_OOXML = "excel_ooxml"
    WORD_OOXML = "word_ooxml"
    POWERPOINT_OOXML = "powerpoint_ooxml"
    PDF = "pdf"
    ENCRYPTED_OOXML = "encrypted_ooxml"
    LEGACY_CFBF = "legacy_cfbf"
    UNKNOWN = "unknown"


class ProtectionLayer(StrEnum):
    SOFT = "soft"
    OPEN_ENCRYPTION = "open_encryption"
    OWNER_PERMISSIONS = "owner_permissions"
    SIGNATURE = "signature"
    VBA = "vba"
    LEGACY = "legacy"


@dataclass(frozen=True)
class ProtectedPart:
    path: str
    kind: str
    count: int = 1


@dataclass(frozen=True)
class ProtectedWorksheet:
    path: str
    protection_count: int


@dataclass(frozen=True)
class WorkbookInspection:
    input_path: Path
    worksheet_protections: tuple[ProtectedWorksheet, ...]
    workbook_protection_count: int
    vba_project_present: bool

    @property
    def worksheet_protection_count(self) -> int:
        return sum(entry.protection_count for entry in self.worksheet_protections)


@dataclass(frozen=True)
class DocumentInspection:
    input_path: Path
    document_format: DocumentFormat
    strategies: tuple[str, ...]
    soft_protections: tuple[ProtectedPart, ...] = ()
    encrypted: bool = False
    signed: bool = False
    vba_project_present: bool = False
    user_password_required: bool = False
    owner_restrictions: bool = False
    notes: tuple[str, ...] = ()
    encryption_scheme: str | None = None
    encryption_version: str | None = None
    encryption_spin_count: int | None = None
    encryption_cost_class: str | None = None
    hashcat_mode: int | None = None
    capabilities: tuple[Capability, ...] = ()
    blockers: tuple[Blocker, ...] = ()
    irm_kind: str | None = None

    def as_workbook_inspection(self) -> WorkbookInspection:
        worksheets = tuple(
            ProtectedWorksheet(path=part.path, protection_count=part.count)
            for part in self.soft_protections
            if part.kind == "sheetProtection"
        )
        workbook_count = sum(
            part.count for part in self.soft_protections if part.kind == "workbookProtection"
        )
        return WorkbookInspection(
            input_path=self.input_path,
            worksheet_protections=worksheets,
            workbook_protection_count=workbook_count,
            vba_project_present=self.vba_project_present,
        )


@dataclass(frozen=True)
class UnlockOptions:
    remove_worksheet_protection: bool = True
    remove_workbook_protection: bool = True
    remove_document_protection: bool = True
    remove_modify_verifier: bool = True
    remove_mark_as_final: bool = True
    strip_pdf_permissions: bool = True
    strip_signatures: bool = False
    unlock_vba: bool = False
    soft_only: bool = False
    password: str | None = None
    wordlist: Path | None = None
    mask: str | None = None
    charset: str | None = None
    max_length: int | None = None
    max_candidates: int = 5_000_000
    workers: int = 1
    overwrite: bool = False
    resign_cert: Path | None = None
    resign_key: Path | None = None
    use_hashcat: bool = False
    hashcat_args: tuple[str, ...] = ()
    hashcat_timeout: int | None = None


@dataclass(frozen=True)
class RemovalCounts:
    worksheet_protections: int = 0
    workbook_protections: int = 0
    document_protections: int = 0
    modify_verifiers: int = 0
    mark_as_final: int = 0
    pdf_permission_strips: int = 0
    signatures_stripped: int = 0
    vba_unlocked: int = 0
    other: int = 0

    @property
    def total(self) -> int:
        return (
            self.worksheet_protections
            + self.workbook_protections
            + self.document_protections
            + self.modify_verifiers
            + self.mark_as_final
            + self.pdf_permission_strips
            + self.signatures_stripped
            + self.vba_unlocked
            + self.other
        )


@dataclass(frozen=True)
class UnlockResult:
    input_path: Path
    output_path: Path
    removed: RemovalCounts
    document_format: DocumentFormat = DocumentFormat.EXCEL_OOXML
    vba_project_present: bool = False
    password_used: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackOptions:
    passwords: tuple[str, ...] = ()
    wordlist: Path | None = None
    mask: str | None = None
    charset: str | None = None
    max_length: int | None = None
    max_candidates: int = 5_000_000
    workers: int = 1
    try_empty: bool = True


@dataclass(frozen=True)
class AttackResult:
    success: bool
    password: str | None = None
    candidates_tried: int = 0
    message: str = ""


__all__ = [
    "AttackOptions",
    "AttackResult",
    "DocumentFormat",
    "DocumentInspection",
    "ProtectionLayer",
    "ProtectedPart",
    "ProtectedWorksheet",
    "RemovalCounts",
    "UnlockOptions",
    "UnlockResult",
    "WorkbookInspection",
]
