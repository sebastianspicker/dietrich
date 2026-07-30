"""Plain-language status copy for the TUI (no product logic).

Legacy line-oriented summaries used by the live app and tests. Prefer
:mod:`dietrich.tui.dossier` for the Werkbank Filing Bench Protection Dossier.
"""

from __future__ import annotations

from dietrich.types import DocumentFormat, DocumentInspection, RemovalCounts, UnlockResult

_FORMAT_LABELS = {
    DocumentFormat.EXCEL_OOXML: "Excel workbook (OOXML)",
    DocumentFormat.WORD_OOXML: "Word document (OOXML)",
    DocumentFormat.POWERPOINT_OOXML: "PowerPoint deck (OOXML)",
    DocumentFormat.PDF: "PDF",
    DocumentFormat.ENCRYPTED_OOXML: "Encrypted Office file",
    DocumentFormat.LEGACY_CFBF: "Binary Office (legacy)",
    DocumentFormat.UNKNOWN: "Unknown format",
}


def format_label(fmt: DocumentFormat) -> str:
    """Human-readable document format name."""
    return _FORMAT_LABELS.get(fmt, fmt.value)


def summarize_inspection(inspection: DocumentInspection) -> list[str]:
    """Return short plain-language lines describing an inspection.

    Kept for backward compatibility with the live app and tests. New UI code
    should use :func:`dietrich.tui.dossier.from_inspection` instead.
    """
    lines: list[str] = [
        f"Format: {format_label(inspection.document_format)}",
    ]

    lines.extend(_inspection_status_lines(inspection))

    if inspection.vba_project_present:
        lines.append("Note: VBA project present - enable “Unlock VBA” only if you need it.")

    for note in inspection.notes[:4]:
        lines.append(f"Note: {note}")

    lines.append("Authorized use only - documents you own or may modify.")
    return lines


def _inspection_status_lines(inspection: DocumentInspection) -> list[str]:
    """Describe the highest-priority inspection finding."""
    if inspection.encrypted or inspection.user_password_required:
        return _encrypted_lines(inspection)
    if inspection.signed:
        return [
            "What we found: digitally signed package.",
            "Recommended: enable “Strip signatures” in Advanced for an unsigned working copy.",
        ]
    if inspection.owner_restrictions:
        return [
            "What we found: PDF owner / permission restrictions.",
            "Recommended: Unlock to strip restrictions (when the file is openable).",
        ]
    if inspection.soft_protections:
        kinds = sorted({p.kind for p in inspection.soft_protections})
        return [
            "What we found: structure locks (not encryption): " + ", ".join(kinds) + ".",
            "Recommended: Unlock - Dietrich will remove soft protection flags.",
        ]
    return [
        "What we found: no soft locks or open-password encryption detected.",
        "Unlock will write a side-by-side copy (may be unchanged).",
    ]


def _encrypted_lines(inspection: DocumentInspection) -> list[str]:
    """Describe open-password encryption and recovery guidance."""
    scheme = inspection.encryption_scheme or "open password"
    lines = [f"What we found: open password required ({scheme})."]
    if inspection.encryption_spin_count:
        suffix = (
            f" ({inspection.encryption_cost_class})"
            if inspection.encryption_cost_class
            else ""
        )
        lines.append(
            f"Encryption cost: spin={inspection.encryption_spin_count}{suffix} - "
            "dictionary attacks can be slow on CPU."
        )
    if inspection.hashcat_mode:
        lines.append(f"Hashcat mode (if exporting): {inspection.hashcat_mode}")
    lines.extend(
        [
            "Recommended: enter a password in Advanced, or provide a wordlist / mask.",
            "Soft-only mode will fail on this file.",
        ]
    )
    return lines


def summarize_result(result: UnlockResult) -> list[str]:
    """Plain-language unlock success summary (never echoes passwords).

    Prefer :func:`dietrich.tui.dossier.from_unlock_result` for dossier UI.
    """
    lines = [
        f"Wrote: {result.output_path}",
        f"Format: {format_label(result.document_format)}",
    ]
    lines.extend(describe_removals(result.removed))
    if result.password_used is not None:
        lines.append("Password: used successfully (not shown).")
    for warning in result.warnings:
        lines.append(f"Warning: {warning}")
    return lines


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
    lines = [f"  · {n} {label}" for n, label in mapping if n]
    if not lines:
        lines.append("  · no protection artefacts removed (copy may be unchanged)")
    return lines
