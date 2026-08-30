"""One-pass document assessment for every interaction adapter."""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path

from dietrich.domain.assessment import Blocker, BlockerCode, Capability, CapabilityCode
from dietrich.domain.models import (
    DocumentFormat,
    DocumentInspection,
    ProtectionLayer,
    WorkbookInspection,
)
from dietrich.errors import (
    EncryptedDocumentError,
    InvalidDocumentError,
    MissingDependencyError,
    UnsupportedFormatError,
)
from dietrich.safety.bounded_io import read_file_prefix

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"


def assess_document(path: Path) -> DocumentInspection:
    """Classify a document and attach typed capabilities and blockers."""
    inspection = _classify_path(Path(path))
    from dietrich.crypto.irm import detect_irm, irm_block_message

    irm = detect_irm(inspection.input_path)
    blockers: list[Blocker] = list(inspection.blockers)
    if irm.is_irm:
        blockers.append(Blocker(BlockerCode.IRM, irm_block_message(irm)))
    if inspection.document_format == DocumentFormat.UNKNOWN:
        blockers.append(Blocker(BlockerCode.UNKNOWN_FORMAT, "Document format is not supported."))
    return replace(
        inspection,
        capabilities=_capabilities_for(inspection),
        blockers=tuple(blockers),
        irm_kind=irm.kind if irm.is_irm else None,
    )


def assess_excel_workbook(path: Path) -> WorkbookInspection:
    """Validate and project the Excel-only compatibility inspection."""
    from dietrich.ooxml.package import inspect_ooxml_package

    inspection = inspect_ooxml_package(Path(path), allow_signed=False)
    if inspection.document_format != DocumentFormat.EXCEL_OOXML:
        raise InvalidDocumentError(f"{path} is not an Excel OOXML workbook.")
    return inspection.as_workbook_inspection()


def enforce_operation_blockers(inspection: DocumentInspection) -> None:
    """Fail every application use case consistently on typed assessment blockers."""
    irm = next(
        (blocker for blocker in inspection.blockers if blocker.code == BlockerCode.IRM), None
    )
    if irm is not None:
        raise EncryptedDocumentError(irm.detail)
    if inspection.blockers:
        raise UnsupportedFormatError(inspection.blockers[0].detail)


def _capabilities_for(inspection: DocumentInspection) -> tuple[Capability, ...]:
    capabilities: dict[CapabilityCode, Capability] = {}
    for strategy in inspection.strategies:
        capability = _capability_for_strategy(strategy)
        if capability is not None:
            capabilities.setdefault(capability.code, capability)
    if inspection.document_format == DocumentFormat.PDF:
        capability = Capability(
            code=CapabilityCode.REMOVE_PDF_RESTRICTIONS,
            layer=ProtectionLayer.OWNER_PERMISSIONS,
            detail="Create an unencrypted PDF working copy without owner restrictions.",
        )
        capabilities.setdefault(capability.code, capability)
    return tuple(capabilities.values())


def _capability_for_strategy(strategy: str) -> Capability | None:
    if strategy.startswith("soft:"):
        return Capability(
            CapabilityCode.REMOVE_SOFT_PROTECTION,
            ProtectionLayer.SOFT,
            "Create an editable copy with supported document flags removed.",
        )
    if strategy.startswith("crypto:") and strategy != "crypto:export_hash":
        return Capability(
            CapabilityCode.RECOVER_OPEN_PASSWORD,
            ProtectionLayer.OPEN_ENCRYPTION,
            "Verify or recover the document open password locally.",
        )
    special = {
        "crypto:export_hash": Capability(
            CapabilityCode.EXPORT_PASSWORD_HASH,
            ProtectionLayer.OPEN_ENCRYPTION,
            "Export password-recovery material for a local external tool.",
        ),
        "signature:strip": Capability(
            CapabilityCode.STRIP_SIGNATURES,
            ProtectionLayer.SIGNATURE,
            "Create an explicitly unsigned working copy.",
        ),
        "vba:unlock": Capability(
            CapabilityCode.CLEAR_VBA_VERIFIER,
            ProtectionLayer.VBA,
            "Clear recognized VBA project password-verifier fields.",
        ),
    }
    return special.get(strategy)


def _classify_path(path: Path) -> DocumentInspection:
    if not path.is_file():
        raise InvalidDocumentError(f"{path} is not a file.")
    header = read_file_prefix(path, 8)
    if header.startswith(PDF_MAGIC):
        return _classify_pdf(path)
    if header.startswith(CFBF_MAGIC):
        return _classify_cfbf(path)
    if header.startswith(ZIP_MAGIC) or header[:2] == b"PK":
        return _classify_ooxml(path)
    return DocumentInspection(
        input_path=path,
        document_format=DocumentFormat.UNKNOWN,
        strategies=(),
        notes=("Unrecognized file magic; cannot classify.",),
    )


def _classify_pdf(path: Path) -> DocumentInspection:
    from dietrich.pdf.inspect import inspect_pdf

    return inspect_pdf(path)


def _classify_ooxml(path: Path) -> DocumentInspection:
    from dietrich.ooxml.package import inspect_ooxml_package

    try:
        return inspect_ooxml_package(path, allow_signed=True)
    except zipfile.BadZipFile:
        return DocumentInspection(
            input_path=path,
            document_format=DocumentFormat.UNKNOWN,
            strategies=(),
            notes=("ZIP magic present but archive is unreadable.",),
        )


def _classify_cfbf(path: Path) -> DocumentInspection:
    fmt, encrypted, strategies, notes, blocker = _cfbf_container_summary(path)
    metadata = _cfbf_encryption_metadata(path, encrypted, notes, strategies)
    return DocumentInspection(
        input_path=path,
        document_format=fmt,
        strategies=tuple(dict.fromkeys(strategies)),
        encrypted=encrypted,
        user_password_required=encrypted,
        notes=tuple(notes),
        blockers=(blocker,) if blocker is not None else (),
        encryption_scheme=metadata[0],
        encryption_version=metadata[1],
        encryption_spin_count=metadata[2],
        encryption_cost_class=metadata[3],
        hashcat_mode=metadata[4],
    )


def _cfbf_container_summary(
    path: Path,
) -> tuple[DocumentFormat, bool, list[str], list[str], Blocker | None]:
    streams = _cfbf_stream_names(path)
    if streams is not None:
        return _cfbf_stream_summary(streams)
    return _cfbf_prefix_summary(path)


def _cfbf_stream_names(path: Path) -> set[str] | None:
    try:
        from dietrich.safety.cfb import list_stream_names

        return list_stream_names(path)
    except (ImportError, OSError, ValueError):
        return None


def _cfbf_stream_summary(
    streams: set[str],
) -> tuple[DocumentFormat, bool, list[str], list[str], Blocker | None]:
    if "EncryptionInfo" in streams or "EncryptedPackage" in streams:
        strategies = [
            "crypto:ooxml_password",
            "crypto:wordlist",
            "crypto:mask",
            "crypto:export_hash",
        ]
        return DocumentFormat.ENCRYPTED_OOXML, True, strategies, [], None
    short_names = {name.rsplit("/", 1)[-1] for name in streams}
    if short_names & {"Workbook", "Book", "WordDocument"}:
        note = "CFBF/OLE binary Office: verified soft-record rewriting available."
        return DocumentFormat.LEGACY_CFBF, False, ["soft:binary_protection"], [note], None
    if "PowerPoint Document" in short_names:
        detail = (
            "Legacy PowerPoint is inspectable, but safe protection rewriting is unavailable "
            "without a verified record parser."
        )
    else:
        detail = "CFBF container is not a supported legacy Office document."
    blocker = Blocker(BlockerCode.UNSUPPORTED_OPERATION, detail)
    return DocumentFormat.LEGACY_CFBF, False, [], [detail], blocker


def _cfbf_prefix_summary(
    path: Path,
) -> tuple[DocumentFormat, bool, list[str], list[str], Blocker | None]:
    blob = read_file_prefix(path, 65_536)
    if b"EncryptionInfo" in blob or b"EncryptedPackage" in blob:
        strategies = ["crypto:ooxml_password", "crypto:wordlist", "crypto:export_hash"]
        return DocumentFormat.ENCRYPTED_OOXML, True, strategies, [], None
    note = "CFBF detected. Install dietrich[legacy] (olefile) for richer inspection."
    return DocumentFormat.LEGACY_CFBF, False, [], [note], None


def _cfbf_encryption_metadata(path: Path, encrypted: bool, notes: list[str], strategies: list[str]):
    if not encrypted:
        return None, None, None, None, None
    try:
        from dietrich.ooxml.encryption import describe_encryption

        metadata = describe_encryption(path)
        notes.extend(metadata.notes)
        if metadata.hashcat_mode:
            strategies.append(f"crypto:hashcat_mode_{metadata.hashcat_mode}")
        return (
            metadata.scheme,
            metadata.version_label,
            metadata.spin_count,
            metadata.cost_class,
            metadata.hashcat_mode,
        )
    except (
        AttributeError,
        EncryptedDocumentError,
        KeyError,
        MissingDependencyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        notes.append(f"Encryption metadata limited: {exc}")
        return None, None, None, None, None


__all__ = ["assess_document", "assess_excel_workbook", "enforce_operation_blockers"]
