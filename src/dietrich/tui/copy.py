"""Small presentation helpers shared by TUI dossier views."""

from __future__ import annotations

from dietrich.domain.models import DocumentFormat, RemovalCounts

_FORMAT_LABELS = {
    DocumentFormat.EXCEL_OOXML: "Excel workbook (OOXML)",
    DocumentFormat.WORD_OOXML: "Word document (OOXML)",
    DocumentFormat.POWERPOINT_OOXML: "PowerPoint deck (OOXML)",
    DocumentFormat.PDF: "PDF",
    DocumentFormat.ENCRYPTED_OOXML: "Encrypted Office file",
    DocumentFormat.LEGACY_CFBF: "Binary Office (legacy)",
    DocumentFormat.UNKNOWN: "Unknown format",
}


def format_label(document_format: DocumentFormat) -> str:
    """Return the user-facing label for one document format."""
    return _FORMAT_LABELS.get(document_format, document_format.value)


def describe_removals(removed: RemovalCounts) -> list[str]:
    """List non-zero removal counts in plain language."""
    mapping = [
        (removed.worksheet_protections, "worksheet protections removed"),
        (removed.workbook_protections, "workbook protections removed"),
        (removed.document_protections, "document protections removed"),
        (removed.modify_verifiers, "modify verifiers removed"),
        (removed.mark_as_final, "mark-as-final flags cleared"),
        (removed.pdf_permission_strips, "PDF permission / encryption strips"),
        (removed.signatures_stripped, "digital signatures stripped"),
        (removed.vba_unlocked, "VBA verifier fields cleared"),
        (removed.other, "other items removed"),
    ]
    lines = [f"  · {count} {label}" for count, label in mapping if count]
    return lines or ["  · no protection artefacts removed (copy may be unchanged)"]


__all__ = ["describe_removals", "format_label"]
