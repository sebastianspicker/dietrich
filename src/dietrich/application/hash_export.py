"""Password-hash export use case."""

from __future__ import annotations

from pathlib import Path

from dietrich.application.assess import assess_document, enforce_operation_blockers
from dietrich.domain.assessment import CapabilityCode
from dietrich.domain.models import DocumentFormat, DocumentInspection
from dietrich.errors import EncryptedDocumentError
from dietrich.operation import checkpoint


def export_document_hash(path: Path, fmt: str = "hashcat") -> str:
    """Export password-recovery material for an Office or PDF document."""
    source = Path(path)
    inspection = assess_document(source)
    return export_assessed_hash(source, inspection, fmt)


def export_assessed_hash(source: Path, inspection: DocumentInspection, fmt: str = "hashcat") -> str:
    """Reuse the checked assessment of the same private snapshot for recovery."""
    if Path(source) != inspection.input_path:
        raise ValueError("assessment does not belong to this source")
    checkpoint("exporting hash")
    enforce_operation_blockers(inspection)
    if CapabilityCode.EXPORT_PASSWORD_HASH not in {
        capability.code for capability in inspection.capabilities
    }:
        raise EncryptedDocumentError(
            f"password hash export is unavailable for {inspection.document_format.value}"
        )
    if inspection.document_format == DocumentFormat.PDF:
        from dietrich.pdf.recovery import export_hash_line

        return export_hash_line(source, fmt)
    if inspection.document_format in {
        DocumentFormat.ENCRYPTED_OOXML,
    }:
        from dietrich.ooxml.encryption import export_hash_line

        return export_hash_line(source, fmt)
    raise EncryptedDocumentError(
        f"hash export not supported for format {inspection.document_format.value}"
    )


__all__ = ["export_document_hash"]
