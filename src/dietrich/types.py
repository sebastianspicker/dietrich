"""Shared dataclasses, enums, and option bags for inspect/unlock results.

These types are the contract between CLI, dispatch, and format handlers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class DocumentFormat(StrEnum):
    """Detected document family used for routing inspect/unlock paths."""

    EXCEL_OOXML = "excel_ooxml"
    WORD_OOXML = "word_ooxml"
    POWERPOINT_OOXML = "powerpoint_ooxml"
    PDF = "pdf"
    ENCRYPTED_OOXML = "encrypted_ooxml"
    LEGACY_CFBF = "legacy_cfbf"
    UNKNOWN = "unknown"


class ProtectionLayer(StrEnum):
    """High-level protection category reported in strategies/notes."""

    SOFT = "soft"
    OPEN_ENCRYPTION = "open_encryption"
    OWNER_PERMISSIONS = "owner_permissions"
    SIGNATURE = "signature"
    VBA = "vba"
    LEGACY = "legacy"


@dataclass(frozen=True)
class ProtectedPart:
    """One soft-protection hit inside a package (ZIP part path + element kind)."""

    path: str
    kind: str
    count: int = 1


@dataclass(frozen=True)
class ProtectedWorksheet:
    """Excel-compat worksheet protection entry."""

    path: str
    protection_count: int


@dataclass(frozen=True)
class WorkbookInspection:
    """Excel-compat inspection result."""

    input_path: Path
    worksheet_protections: tuple[ProtectedWorksheet, ...]
    workbook_protection_count: int
    vba_project_present: bool

    @property
    def worksheet_protection_count(self) -> int:
        """Total sheetProtection counts across worksheet parts."""
        return sum(entry.protection_count for entry in self.worksheet_protections)


@dataclass(frozen=True)
class DocumentInspection:
    """Multi-format inspect result: format, soft hits, crypto metadata, strategies."""

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
    # Hard-encryption metadata (open password)
    encryption_scheme: str | None = None
    encryption_version: str | None = None
    encryption_spin_count: int | None = None
    encryption_cost_class: str | None = None
    hashcat_mode: int | None = None

    def as_workbook_inspection(self) -> WorkbookInspection:
        """Project multi-format soft hits into the Excel-compat WorkbookInspection shape."""
        worksheets = tuple(
            ProtectedWorksheet(path=p.path, protection_count=p.count)
            for p in self.soft_protections
            if p.kind == "sheetProtection"
        )
        workbook_count = sum(
            p.count for p in self.soft_protections if p.kind == "workbookProtection"
        )
        return WorkbookInspection(
            input_path=self.input_path,
            worksheet_protections=worksheets,
            workbook_protection_count=workbook_count,
            vba_project_present=self.vba_project_present,
        )


@dataclass(frozen=True)
class UnlockOptions:
    """Flags for soft strip, open-password recovery, re-sign, and hashcat orchestration."""

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
    # Honest re-sign (user cert/key PEM paths)
    resign_cert: Path | None = None
    resign_key: Path | None = None
    # hashcat orchestration
    use_hashcat: bool = False
    hashcat_args: tuple[str, ...] = ()
    hashcat_timeout: int | None = None


@dataclass(frozen=True)
class RemovalCounts:
    """How many of each soft/signature/VBA artefact the unlock path removed."""

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
        """Sum of all counted removals (for CLI summary)."""
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
    """Outcome of a successful unlock write (paths, counts, optional password, warnings)."""

    input_path: Path
    output_path: Path
    removed: RemovalCounts
    document_format: DocumentFormat = DocumentFormat.EXCEL_OOXML
    vba_project_present: bool = False
    password_used: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackOptions:
    """Candidate sources and caps for local password verification attacks."""

    passwords: tuple[str, ...] = ()
    wordlist: Path | None = None
    mask: str | None = None
    charset: str | None = None
    max_length: int | None = None
    max_candidates: int = 5_000_000
    workers: int = 1
    try_empty: bool = True


@dataclass
class AttackProgress:
    """Mutable progress snapshot for multi-worker password attacks."""

    tried: int = 0
    found: str | None = None


@dataclass(frozen=True)
class AttackResult:
    """Result of a password recovery attempt (found password or failure message)."""

    success: bool
    password: str | None = None
    candidates_tried: int = 0
    message: str = ""


@dataclass(frozen=True)
class PartStats:
    """Mutable-friendly merge target for transformer stats."""

    counts: dict[str, int] = field(default_factory=dict)

    def add(self, key: str, n: int = 1) -> None:
        """Accumulate n hits under a transformer key (e.g. sheetProtection)."""
        if n:
            self.counts[key] = self.counts.get(key, 0) + n

    def to_removal_counts(self) -> RemovalCounts:
        """Map internal transformer keys to the public RemovalCounts fields."""
        return RemovalCounts(
            worksheet_protections=self.counts.get("sheetProtection", 0),
            workbook_protections=self.counts.get("workbookProtection", 0),
            document_protections=self.counts.get("documentProtection", 0),
            modify_verifiers=self.counts.get("modifyVerifier", 0),
            mark_as_final=self.counts.get("markAsFinal", 0),
            pdf_permission_strips=self.counts.get("pdfPermissions", 0),
            signatures_stripped=self.counts.get("signatures", 0),
            vba_unlocked=self.counts.get("vba", 0),
            other=self.counts.get("other", 0),
        )
