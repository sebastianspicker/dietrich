"""Protection Dossier view-model for the Werkbank Filing Bench TUI.

Pure functions and dataclasses only - no Textual imports. The app layer maps
:class:`DossierView` onto status-heading / status / status-meta widgets.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dietrich.tui.copy import describe_removals, format_label
from dietrich.types import DocumentInspection, ProtectedPart, UnlockResult

# Diagnosis titles - exact Filing Bench wording.
_TITLE_OPEN_PASSWORD = "Open password required"
_TITLE_SIGNED = "Digitally signed package"
_TITLE_OWNER = "PDF owner restrictions"
_TITLE_SOFT = "Soft structure locks"
_TITLE_NONE = "No locks detected"
_TITLE_UNLOCK_OK = "Unlock complete"
_TITLE_UNLOCK_WARN = "Unlock complete · warning"


@dataclass(frozen=True)
class DossierView:
    """Structured protection dossier for the status panel.

    ``findings`` entries are ``(label, value, tone)`` with tone in
    ``{"ok", "warn", "signal", "neutral"}``.
    ``state`` drives panel chrome: ``"info" | "ok" | "warning" | "error"``.
    """

    heading: str
    title: str
    lede: str
    findings: tuple[tuple[str, str, str], ...]
    next_step: str
    metadata: str
    state: str


def empty_dossier() -> DossierView:
    """Ready state before any inspect - quiet intake prompt."""
    return DossierView(
        heading="READY TO INSPECT",
        title="",
        lede="Paste a document path, then Inspect.",
        findings=(),
        next_step="Open a local file, then Inspect.",
        metadata="SIGNED  -\nIRM GATE  ACTIVE",
        state="info",
    )


def error_dossier(heading: str, message: str) -> DossierView:
    """Hard-stop dossier (missing path, inspect/unlock failure)."""
    return DossierView(
        heading=heading,
        title="",
        lede=message,
        findings=(),
        next_step="",
        metadata="SIGNED  -\nIRM GATE  ACTIVE",
        state="error",
    )


def busy_dossier(heading: str, message: str, state: str = "info") -> DossierView:
    """In-progress dossier (Inspecting / Unlocking)."""
    return DossierView(
        heading=heading,
        title="",
        lede=message,
        findings=(),
        next_step="",
        metadata="SIGNED  -\nIRM GATE  ACTIVE",
        state=state,
    )


def from_inspection(inspection: DocumentInspection) -> DossierView:
    """Build a dossier from a successful :class:`DocumentInspection`."""
    title, lede, next_step = _diagnose(inspection)
    findings = _inspection_findings(inspection)
    metadata = _signed_metadata(inspection.signed)
    return DossierView(
        heading="INSPECTION COMPLETE",
        title=title,
        lede=lede,
        findings=findings,
        next_step=next_step,
        metadata=metadata,
        state="info",
    )


def from_unlock_result(result: UnlockResult) -> DossierView:
    """Build a dossier after a successful unlock write (never echoes passwords)."""
    has_warnings = bool(result.warnings)
    title = _TITLE_UNLOCK_WARN if has_warnings else _TITLE_UNLOCK_OK
    heading = "UNLOCK COMPLETE · WARNING" if has_warnings else "UNLOCK COMPLETE"
    state = "warning" if has_warnings else "ok"

    wrote = _short_path(result.output_path)
    lede = f"Wrote: {wrote}"
    if result.password_used is not None:
        lede = f"{lede} Password used successfully (not shown)."

    findings = _removal_findings(result)
    if result.warnings:
        # Surface first warnings as finding rows (keep compact).
        for warning in result.warnings[:2]:
            findings = (*findings, ("Warning", warning, "warn"))

    next_step = (
        "Review warnings, then use the working copy if appropriate."
        if has_warnings
        else "Working copy ready - original file is unchanged."
    )
    return DossierView(
        heading=heading,
        title=title,
        lede=lede,
        findings=findings,
        next_step=next_step,
        metadata="SIGNED  -\nIRM GATE  ACTIVE",
        state=state,
    )


def format_dossier_body(view: DossierView) -> list[str]:
    """Plain lines for the status Static: title, lede, findings, next step.

    Kept under ~12 lines for terminal height.
    """
    lines: list[str] = []
    if view.title:
        lines.append(view.title)
    if view.lede:
        lines.append(view.lede)
    for label, value, _tone in view.findings:
        lines.append(f"{label} · {value}")
    if view.next_step:
        lines.append(f"Next · {view.next_step}")
    return lines[:12]


# --- internals --------------------------------------------------------------


def _diagnose(inspection: DocumentInspection) -> tuple[str, str, str]:
    """Return (title, lede, next_step) from protection priority order."""
    if inspection.encrypted or inspection.user_password_required:
        scheme = inspection.encryption_scheme or "open password"
        lede = f"Open password required ({scheme}). Soft-only mode will fail on this file."
        next_step = "Enter a password in Advanced, or provide a wordlist / mask."
        return _TITLE_OPEN_PASSWORD, lede, next_step

    if inspection.signed:
        lede = "Package is digitally signed. Unlock leaves signatures unless strip is enabled."
        next_step = 'Enable "Strip signatures" in Advanced for an unsigned working copy.'
        return _TITLE_SIGNED, lede, next_step

    if inspection.owner_restrictions:
        lede = (
            "PDF owner / permission restrictions are set. This is not the same as open encryption."
        )
        next_step = "Unlock to strip restrictions (when the file is openable)."
        return _TITLE_OWNER, lede, next_step

    if inspection.soft_protections:
        summary = _soft_hits_summary(inspection.soft_protections)
        lede = f"{summary}. These are application flags - not encryption."
        next_step = "Unlock a side-by-side working copy. Original stays unchanged."
        return _TITLE_SOFT, lede, next_step

    lede = "No soft locks or open-password encryption detected on this path."
    next_step = "Unlock will write a side-by-side copy (may be unchanged)."
    return _TITLE_NONE, lede, next_step


def _inspection_findings(
    inspection: DocumentInspection,
) -> tuple[tuple[str, str, str], ...]:
    """Finding rows for the dossier grid (label, value, tone)."""
    rows: list[tuple[str, str, str]] = []

    # Soft hits
    if inspection.soft_protections:
        rows.append(("Soft hits", _soft_hits_value(inspection.soft_protections), "warn"))
    else:
        rows.append(("Soft hits", "None", "ok"))

    rows.extend(_password_findings(inspection))

    # Signed
    rows.append(
        ("Signed", "Yes" if inspection.signed else "No", "warn" if inspection.signed else "ok")
    )

    # IRM - pure path does not call detect_irm; note-driven or default.
    rows.append(_irm_finding(inspection.notes))

    # Format (short)
    rows.append(("Format", format_label(inspection.document_format), "neutral"))

    rows.extend(_optional_findings(inspection))

    return tuple(rows)


def _password_findings(inspection: DocumentInspection) -> list[tuple[str, str, str]]:
    """Return dossier rows for open-password metadata."""
    if not (inspection.encrypted or inspection.user_password_required):
        return [("Open password", "Not required", "ok")]
    scheme = inspection.encryption_scheme or "required"
    rows = [("Open password", f"Required ({scheme})", "signal")]
    if inspection.encryption_spin_count is not None:
        cost = f"spin={inspection.encryption_spin_count}"
        if inspection.encryption_cost_class:
            cost += f" · {inspection.encryption_cost_class}"
        rows.append(("Encryption cost", cost, "warn"))
    return rows


def _optional_findings(inspection: DocumentInspection) -> list[tuple[str, str, str]]:
    """Return dossier rows for optional protection metadata."""
    rows: list[tuple[str, str, str]] = []
    if inspection.owner_restrictions:
        rows.append(("Owner restrictions", "Yes", "warn"))
    if inspection.vba_project_present:
        rows.append(("VBA project", "Present - enable Unlock VBA only if needed", "neutral"))
    if inspection.hashcat_mode is not None:
        rows.append(("Hashcat mode", str(inspection.hashcat_mode), "neutral"))
    return rows


def _irm_finding(notes: tuple[str, ...]) -> tuple[str, str, str]:
    """IRM / Purview row without calling detect_irm.

    Default: "None detected" (gate still shown in metadata as ACTIVE).
    Notes that mention IRM/Purview/RMS surface as "Flagged".
    """
    joined = " ".join(notes).lower()
    if any(token in joined for token in ("irm", "purview", "rms", "rights management")):
        return ("IRM / Purview", "Flagged", "signal")
    return ("IRM / Purview", "None detected", "ok")


def _soft_hits_summary(parts: tuple[ProtectedPart, ...]) -> str:
    """One-sentence soft-protection summary for the lede."""
    by_kind = _aggregate_kinds(parts)
    total = sum(by_kind.values())
    kinds = ", ".join(by_kind)
    if len(by_kind) == 1:
        kind, count = next(iter(by_kind.items()))
        noun = "flag" if count == 1 else "flags"
        return f"{count} {kind} {noun} set"
    return f"{total} structure locks across {len(by_kind)} kinds ({kinds})"


def _soft_hits_value(parts: tuple[ProtectedPart, ...]) -> str:
    """Compact value for the Soft hits finding chip."""
    by_kind = _aggregate_kinds(parts)
    bits = [f"{count} · {kind}" for kind, count in by_kind.items()]
    return "; ".join(bits)


def _aggregate_kinds(parts: tuple[ProtectedPart, ...]) -> dict[str, int]:
    """Sum counts per protection kind (stable insertion order)."""
    by_kind: dict[str, int] = {}
    for part in parts:
        by_kind[part.kind] = by_kind.get(part.kind, 0) + part.count
    return by_kind


def _removal_findings(result: UnlockResult) -> tuple[tuple[str, str, str], ...]:
    """Map removal counts into finding rows for the unlock dossier."""
    lines = describe_removals(result.removed)
    rows: list[tuple[str, str, str]] = [
        ("Format", format_label(result.document_format), "neutral"),
    ]
    for line in lines:
        text = line.lstrip(" ·")
        if text.startswith("no protection"):
            rows.append(("Removals", "None (copy may be unchanged)", "ok"))
        else:
            rows.append(("Removed", text, "ok"))
    return tuple(rows)


def _signed_metadata(signed: bool) -> str:
    """Status-meta block matching live app copy."""
    return f"SIGNED  {'YES' if signed else 'NO'}\nIRM GATE  ACTIVE"


def _short_path(path: Path) -> str:
    """Prefer basename for the dossier lede; keep parent if bare."""
    name = path.name
    return name if name else str(path)
