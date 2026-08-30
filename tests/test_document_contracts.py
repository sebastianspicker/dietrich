"""Observable document, API, and command-line contracts."""

from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, export_document_hash, inspect_document, unlock_document
from dietrich.cli import main
from dietrich.domain.assessment import BlockerCode, CapabilityCode
from dietrich.errors import (
    EncryptedDocumentError,
    InvalidDocumentError,
    SignedDocumentError,
    UnsupportedFormatError,
)


@pytest.mark.parametrize(
    ("suffix", "main_part", "member", "content", "removed_field", "removed_text"),
    [
        (
            ".xlsx",
            "xl/workbook.xml",
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetProtection/><sheetData/></worksheet>",
            "worksheet_protections",
            b"sheetProtection",
        ),
        (
            ".docx",
            "word/document.xml",
            "word/settings.xml",
            b'<w:settings xmlns:w="w"><w:documentProtection/></w:settings>',
            "document_protections",
            b"documentProtection",
        ),
        (
            ".pptx",
            "ppt/presentation.xml",
            "ppt/presentation.xml",
            b'<p:presentation xmlns:p="p"><p:modifyVerifier/></p:presentation>',
            "modify_verifiers",
            b"modifyVerifier",
        ),
    ],
)
def test_supported_ooxml_formats_produce_editable_private_copies(
    tmp_path: Path,
    suffix: str,
    main_part: str,
    member: str,
    content: bytes,
    removed_field: str,
    removed_text: bytes,
) -> None:
    source = tmp_path / f"protected{suffix}"
    output = tmp_path / f"editable{suffix}"
    with zipfile.ZipFile(source, "w") as archive:
        if main_part != member:
            archive.writestr(main_part, b"<document/>")
        archive.writestr(member, content)

    result = unlock_document(source, output)

    assert getattr(result.removed, removed_field) == 1
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with zipfile.ZipFile(output) as archive:
        assert removed_text not in archive.read(member)


def test_assessment_exposes_typed_capabilities_and_blockers(tmp_path: Path) -> None:
    workbook = tmp_path / "protected.xlsx"
    with zipfile.ZipFile(workbook, "w") as archive:
        archive.writestr("xl/workbook.xml", b"<workbook><workbookProtection/></workbook>")
    assessment = inspect_document(workbook)
    assert CapabilityCode.REMOVE_SOFT_PROTECTION in {
        capability.code for capability in assessment.capabilities
    }
    assert assessment.blockers == ()

    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"unknown")
    assessment = inspect_document(unknown)
    assert [blocker.code for blocker in assessment.blockers] == [BlockerCode.UNKNOWN_FORMAT]


def test_irm_is_assessed_once_and_blocks_transformation(tmp_path: Path) -> None:
    source = tmp_path / "rights-managed.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("word/document.xml", b"<document/>")
        archive.writestr("customXml/rightsManagement.xml", b"<rightsManagement/>")
    assessment = inspect_document(source)
    assert assessment.irm_kind == "ooxml_irm"
    assert [blocker.code for blocker in assessment.blockers] == [BlockerCode.IRM]

    with pytest.raises(EncryptedDocumentError, match="IRM|rights management"):
        unlock_document(source, tmp_path / "should-not-exist.docx")
    assert not (tmp_path / "should-not-exist.docx").exists()


def test_irm_blocker_prevents_hash_backend_invocation(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "rights-managed.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("word/document.xml", b"<document/>")
        archive.writestr("customXml/rightsManagement.xml", b"<rightsManagement/>")

    called = False

    def forbidden_backend(*args, **kwargs):
        nonlocal called
        called = True
        return "sentinel"

    monkeypatch.setattr("dietrich.ooxml.encryption.export_hash_line", forbidden_backend)
    with pytest.raises(EncryptedDocumentError, match="IRM|rights management"):
        export_document_hash(source)
    assert not called


@pytest.mark.parametrize("kind", ["unknown", "unencrypted_ooxml"])
def test_hash_backend_requires_supported_export_capability(
    tmp_path: Path, monkeypatch, kind: str
) -> None:
    source = tmp_path / ("unknown.bin" if kind == "unknown" else "plain.xlsx")
    if kind == "unknown":
        source.write_bytes(b"not a document")
    else:
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("xl/workbook.xml", b"<workbook/>")

    called = False

    def forbidden_backend(*args, **kwargs):
        nonlocal called
        called = True
        return "sentinel"

    monkeypatch.setattr("dietrich.ooxml.encryption.export_hash_line", forbidden_backend)
    with pytest.raises((EncryptedDocumentError, UnsupportedFormatError)):
        export_document_hash(source)
    assert not called


def test_signed_package_fails_closed_or_strips_explicitly(tmp_path: Path) -> None:
    source = tmp_path / "signed.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", b"<workbook/>")
        archive.writestr("_xmlsignatures/sig1.xml", b"<Signature/>")
    with pytest.raises(SignedDocumentError):
        unlock_document(source, tmp_path / "rejected.xlsx")

    output = tmp_path / "unsigned.xlsx"
    result = unlock_document(source, output, UnlockOptions(strip_signatures=True))
    assert result.removed.signatures_stripped == 1
    with zipfile.ZipFile(output) as archive:
        assert not any(name.startswith("_xmlsignatures/") for name in archive.namelist())


def test_failure_before_commit_leaves_target_absent(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", b"<workbook/>")
    target = tmp_path / "target.xlsx"

    def fail_signing(*args, **kwargs):
        raise InvalidDocumentError("verification failed")

    monkeypatch.setattr("dietrich.ooxml.signatures.resign.write_signed_candidate", fail_signing)
    options = UnlockOptions(resign_cert=tmp_path / "cert.pem", resign_key=tmp_path / "key.pem")
    with pytest.raises(InvalidDocumentError, match="verification failed"):
        unlock_document(source, target, options)
    assert not target.exists()
    assert list(tmp_path.glob(f".{target.name}.*")) == []


def test_cli_json_and_exit_code_contract(tmp_path: Path, capsys) -> None:
    source = tmp_path / "book.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", b"<workbook/>")

    assert main([str(source), "--inspect", "--json"]) == 0
    inspection = json.loads(capsys.readouterr().out)
    assert set(inspection) == {
        "input_path",
        "document_format",
        "strategies",
        "soft_protections",
        "encrypted",
        "signed",
        "vba_project_present",
        "user_password_required",
        "owner_restrictions",
        "encryption_scheme",
        "encryption_version",
        "encryption_spin_count",
        "encryption_cost_class",
        "hashcat_mode",
        "notes",
    }

    output = tmp_path / "out.xlsx"
    assert main([str(source), "--output", str(output), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["output_path"] == str(output)
    assert result["password_recovered"] is False
    assert main([str(source), "--output", str(output)]) == 2
    assert "Use --force" in capsys.readouterr().err


def test_invalid_workbook_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "invalid.xlsx"
    source.write_bytes(b"not a ZIP")
    with pytest.raises(InvalidDocumentError, match="valid OOXML ZIP"):
        from dietrich import inspect_workbook

        inspect_workbook(source)


def test_arbitrary_zip_with_office_suffix_is_never_published(tmp_path: Path) -> None:
    source = tmp_path / "disguised.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("payload.txt", b"not an Office package")

    from dietrich import inspect_workbook

    with pytest.raises(InvalidDocumentError, match="Excel OOXML"):
        inspect_workbook(source)
    target = tmp_path / "target.xlsx"
    with pytest.raises(UnsupportedFormatError, match="not supported"):
        unlock_document(source, target)
    assert not target.exists()


@pytest.mark.parametrize(
    "members",
    [
        {"xl/junk.txt": b"prefix-shaped decoy"},
        {"xl/workbook.xml": b"<workbook/>", "word/document.xml": b"<document/>"},
    ],
)
def test_ooxml_identity_requires_one_defining_main_part(
    tmp_path: Path, members: dict[str, bytes]
) -> None:
    source = tmp_path / "decoy.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)

    inspection = inspect_document(source)
    assert inspection.document_format.value == "unknown"
    target = tmp_path / "target.xlsx"
    with pytest.raises(UnsupportedFormatError):
        unlock_document(source, target)
    assert not target.exists()


def test_workbook_unlock_rejects_word_package_with_xlsx_suffix(tmp_path: Path) -> None:
    from dietrich import unlock_workbook

    source = tmp_path / "not-a-workbook.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("word/document.xml", b"<document/>")
    target = tmp_path / "target.xlsx"

    with pytest.raises(InvalidDocumentError, match="excel_ooxml|Excel OOXML"):
        unlock_workbook(source, target, UnlockOptions())
    assert not target.exists()


def test_plain_pdf_does_not_claim_restrictions_were_removed(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    source = tmp_path / "plain.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page()
        pdf.save(source)

    result = unlock_document(source, tmp_path / "copy.pdf")

    assert result.removed.pdf_permission_strips == 0
    assert result.warnings == ()


def test_owner_restricted_pdf_reports_one_permission_strip(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    source = tmp_path / "restricted.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page()
        pdf.save(
            source,
            encryption=pikepdf.Encryption(
                owner="owner-secret",
                user="",
                allow=pikepdf.Permissions(extract=False),
                R=4,
            ),
        )

    output = tmp_path / "unrestricted.pdf"
    result = unlock_document(source, output)

    assert result.removed.pdf_permission_strips == 1
    assert result.warnings == ("PDF encryption/restrictions removed from working copy.",)
    with pikepdf.open(output) as pdf:
        assert not pdf.is_encrypted


def test_user_password_pdf_is_decrypted_with_explicit_password(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    document_key = "viewer-passphrase"
    source = tmp_path / "password.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page()
        pdf.save(
            source,
            encryption=pikepdf.Encryption(owner="editor-passphrase", user="viewer-passphrase", R=4),
        )

    output = tmp_path / "decrypted.pdf"
    result = unlock_document(source, output, UnlockOptions(password=document_key))

    assert result.password_used == document_key
    assert result.removed.pdf_permission_strips == 1
    with pikepdf.open(output) as pdf:
        assert not pdf.is_encrypted


def test_tui_entry_point_has_noninteractive_help(capsys) -> None:
    from dietrich.tui import main as tui_main

    assert tui_main(["--help"]) == 0
    assert capsys.readouterr().out.startswith("usage: dietrich-tui")
