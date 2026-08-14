"""Unit tests for the pure protection-dossier view model."""

from __future__ import annotations

from pathlib import Path

from dietrich.tui.dossier import (
    DossierView,
    busy_dossier,
    empty_dossier,
    error_dossier,
    format_dossier_body,
    from_inspection,
    from_unlock_result,
)
from dietrich.types import (
    DocumentFormat,
    DocumentInspection,
    ProtectedPart,
    RemovalCounts,
    UnlockResult,
)


def test_empty_dossier() -> None:
    view = empty_dossier()
    assert view.heading == "READY TO INSPECT"
    assert "Inspect" in view.lede
    assert view.state == "info"
    assert "IRM GATE  ACTIVE" in view.metadata
    assert not view.findings


def test_error_and_busy_dossier() -> None:
    err = error_dossier("FILE NOT FOUND", "File not found: /tmp/x.xlsx")
    assert err.state == "error"
    assert "File not found" in err.lede
    assert err.heading == "FILE NOT FOUND"

    busy = busy_dossier("INSPECTING", "Reading local document structure…")
    assert busy.state == "info"
    assert busy.heading == "INSPECTING"


def test_from_inspection_soft() -> None:
    view = from_inspection(_soft_protection_inspection())
    _assert_soft_dossier(view)


def _soft_protection_inspection() -> DocumentInspection:
    """Return the compact soft-protection inspection used by dossier assertions."""
    return DocumentInspection(
        input_path=Path("book.xlsx"),
        document_format=DocumentFormat.EXCEL_OOXML,
        strategies=("soft:sheetProtection",),
        soft_protections=(ProtectedPart("xl/worksheets/sheet1.xml", "sheetProtection", 1),),
    )


def _assert_soft_dossier(view: DossierView) -> None:
    """Assert the public dossier representation for soft protection inspection."""
    _assert_soft_dossier_header(view)
    _assert_soft_dossier_findings(view)
    _assert_soft_dossier_body(view)


def _assert_soft_dossier_header(view: DossierView) -> None:
    """Assert the fixed heading and metadata for a soft-protection dossier."""
    assert view.heading == "INSPECTION COMPLETE"
    assert view.title == "Soft structure locks"
    assert "not encryption" in view.lede.lower()
    assert view.state == "info"
    assert "SIGNED  NO" in view.metadata
    assert "IRM GATE  ACTIVE" in view.metadata


def _assert_soft_dossier_findings(view: DossierView) -> None:
    """Assert the semantic dossier rows for a soft-protection inspection."""
    labels = {label for label, _v, _t in view.findings}
    assert "Soft hits" in labels
    assert "Open password" in labels
    assert "Signed" in labels
    assert "IRM / Purview" in labels
    assert "Format" in labels

    soft = next(v for lab, v, _t in view.findings if lab == "Soft hits")
    assert "sheetProtection" in soft
    open_pw = next(v for lab, v, _t in view.findings if lab == "Open password")
    assert open_pw == "Not required"
    irm = next(v for lab, v, _t in view.findings if lab == "IRM / Purview")
    assert irm == "None detected"


def _assert_soft_dossier_body(view: DossierView) -> None:
    """Assert the compact text rendering remains bounded and actionable."""
    body = format_dossier_body(view)
    assert body[0] == "Soft structure locks"
    assert any("Soft hits ·" in line for line in body)
    assert any(line.startswith("Next ·") for line in body)
    assert len(body) <= 12


def test_from_inspection_encrypted() -> None:
    insp = DocumentInspection(
        input_path=Path("secret.xlsx"),
        document_format=DocumentFormat.ENCRYPTED_OOXML,
        strategies=("crypto:ooxml_password",),
        encrypted=True,
        user_password_required=True,
        encryption_scheme="agile",
        encryption_spin_count=100_000,
        encryption_cost_class="expensive",
        hashcat_mode=9600,
    )
    view = from_inspection(insp)
    assert view.title == "Open password required"
    assert "open password" in view.lede.lower() or "agile" in view.lede.lower()
    assert "Soft-only" in view.lede or "soft-only" in view.lede.lower()
    open_pw = next(v for lab, v, _t in view.findings if lab == "Open password")
    assert "Required" in open_pw
    assert "agile" in open_pw
    body = "\n".join(format_dossier_body(view))
    assert "Open password required" in body
    assert "password" in view.next_step.lower() or "wordlist" in view.next_step.lower()


def test_from_inspection_empty_locks() -> None:
    insp = DocumentInspection(
        input_path=Path("clean.docx"),
        document_format=DocumentFormat.WORD_OOXML,
        strategies=(),
    )
    view = from_inspection(insp)
    assert view.title == "No locks detected"
    soft = next(v for lab, v, _t in view.findings if lab == "Soft hits")
    assert soft == "None"
    assert view.state == "info"


def test_from_inspection_signed_and_vba() -> None:
    insp = DocumentInspection(
        input_path=Path("signed.xlsx"),
        document_format=DocumentFormat.EXCEL_OOXML,
        strategies=("signature",),
        signed=True,
        vba_project_present=True,
    )
    view = from_inspection(insp)
    assert view.title == "Digitally signed package"
    assert "SIGNED  YES" in view.metadata
    labels = {lab for lab, _v, _t in view.findings}
    assert "VBA project" in labels
    signed_val = next(v for lab, v, _t in view.findings if lab == "Signed")
    assert signed_val == "Yes"


def test_from_inspection_owner_restrictions() -> None:
    insp = DocumentInspection(
        input_path=Path("locked.pdf"),
        document_format=DocumentFormat.PDF,
        strategies=("owner",),
        owner_restrictions=True,
    )
    view = from_inspection(insp)
    assert view.title == "PDF owner restrictions"


def test_from_unlock_result_ok_and_warning() -> None:
    ok = UnlockResult(
        input_path=Path("in.xlsx"),
        output_path=Path("out.xlsx"),
        removed=RemovalCounts(worksheet_protections=1),
        password_used="should-not-appear",
    )
    view = from_unlock_result(ok)
    assert view.title == "Unlock complete"
    assert view.state == "ok"
    body = "\n".join(format_dossier_body(view))
    assert "should-not-appear" not in body
    assert "out.xlsx" in view.lede or "Wrote" in view.lede

    warn = UnlockResult(
        input_path=Path("in.xlsx"),
        output_path=Path("out.xlsx"),
        removed=RemovalCounts(),
        warnings=("note one",),
    )
    wview = from_unlock_result(warn)
    assert wview.title == "Unlock complete · warning"
    assert wview.state == "warning"
    assert wview.heading == "UNLOCK COMPLETE · WARNING"


def test_format_dossier_body_caps_lines() -> None:
    findings = tuple(("L", f"v{i}", "neutral") for i in range(20))
    view = DossierView(
        heading="H",
        title="Title",
        lede="Lede text",
        findings=findings,
        next_step="Do the thing.",
        metadata="SIGNED  NO\nIRM GATE  ACTIVE",
        state="info",
    )
    body = format_dossier_body(view)
    assert len(body) <= 12
    assert body[0] == "Title"
    assert body[1] == "Lede text"
