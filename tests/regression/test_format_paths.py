"""Regression coverage for legacy, PDF, signing, IRM, and hashcat paths."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, export_document_hash, unlock_document
from dietrich.crypto.irm import detect_irm
from dietrich.legacy.binary_soft import unlock_binary_office
from dietrich.legacy.cfb_io import patch_streams, read_streams
from dietrich.types import DocumentFormat
from tests.support.cli import make_self_signed_pem
from tests.support.fixtures import FIXTURES
from tests.support.ooxml import write_ooxml


@pytest.mark.skipif(not (FIXTURES / "plain.xls").is_file(), reason="plain.xls missing")
def test_binary_xls_soft_clears_protect_records(tmp_path: Path) -> None:
    src = FIXTURES / "plain.xls"
    streams = read_streams(src)
    key = "Workbook"
    wb = bytearray(streams[key])
    idx = wb.find(b"\x00" * 16)
    assert idx >= 0
    struct.pack_into("<HH", wb, idx, 0x0012, 2)
    struct.pack_into("<H", wb, idx + 4, 1)
    struct.pack_into("<HH", wb, idx + 6, 0x0013, 2)
    struct.pack_into("<H", wb, idx + 10, 0xABCD)
    mod = tmp_path / "mod.xls"
    patch_streams(src, mod, {key: bytes(wb)})
    out = tmp_path / "out.xls"
    result = unlock_binary_office(mod, out, UnlockOptions())
    assert result.removed.worksheet_protections >= 1
    cleared = read_streams(out)[key]
    assert cleared[idx + 4 : idx + 6] == b"\x00\x00"
    assert cleared[idx + 10 : idx + 12] == b"\x00\x00"


@pytest.mark.skipif(not (FIXTURES / "plain.doc").is_file(), reason="plain.doc missing")
def test_binary_doc_unlock_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "out.doc"
    result = unlock_document(FIXTURES / "plain.doc", out, UnlockOptions())
    assert out.is_file()
    assert result.document_format == DocumentFormat.LEGACY_CFBF


@pytest.mark.skipif(not (FIXTURES / "plain.ppt").is_file(), reason="plain.ppt missing")
def test_binary_ppt_unlock_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "out.ppt"
    unlock_document(FIXTURES / "plain.ppt", out, UnlockOptions())
    assert out.is_file()


def test_native_pdf_hash_export(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    pdf_path = tmp_path / "u.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    # User password required
    pdf.save(
        pdf_path,
        encryption=pikepdf.Encryption(user="secret", owner="owner", R=4),
    )
    # Native export should not require pdf2john
    line = export_document_hash(pdf_path, "hashcat")
    assert line.startswith("$pdf$")
    assert "secret" not in line  # hash, not password


def test_irm_detect_clean_ooxml(tmp_path: Path) -> None:
    p = tmp_path / "a.xlsx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", b"<Types/>")
        z.writestr("xl/workbook.xml", b"<workbook/>")
    info = detect_irm(p)
    assert info.is_irm is False


def test_hashcat_mode_suggest_office() -> None:
    from dietrich.crypto.hashcat_runner import suggest_mode_from_hash

    assert suggest_mode_from_hash("$office$201310000025616aabb*cc") == 9600
    assert suggest_mode_from_hash("$office$20072012816aabb*cc") == 9400


def test_resign_on_binary_xls_raises_not_silent_noop(tmp_path: Path) -> None:
    """Resign flags on non-OOXML must error, not succeed quietly."""
    from dietrich.errors import UnsupportedFormatError

    xls = FIXTURES / "plain.xls"
    if not xls.is_file():
        pytest.skip("plain.xls missing")
    pytest.importorskip("cryptography")
    cert_pem, key_pem = make_self_signed_pem(tmp_path)
    out = tmp_path / "out.xls"
    with pytest.raises(UnsupportedFormatError, match="cannot --resign"):
        unlock_document(
            xls,
            out,
            UnlockOptions(resign_cert=cert_pem, resign_key=key_pem, overwrite=True),
        )


def test_resign_on_pdf_raises_not_silent_noop(tmp_path: Path) -> None:
    """Resign flags on PDF must error, not succeed quietly."""
    pikepdf = pytest.importorskip("pikepdf")
    from dietrich.errors import UnsupportedFormatError

    pdf_path = tmp_path / "a.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    pdf.save(pdf_path)
    pytest.importorskip("cryptography")
    cert_pem, key_pem = make_self_signed_pem(tmp_path)
    out = tmp_path / "out.pdf"
    with pytest.raises(UnsupportedFormatError, match="cannot --resign"):
        unlock_document(
            pdf_path,
            out,
            UnlockOptions(resign_cert=cert_pem, resign_key=key_pem, overwrite=True),
        )


def test_resign_runs_after_encrypted_ooxml_unlock(tmp_path: Path) -> None:
    """--resign-cert/--resign-key must apply after open-password decrypt (not silent no-op)."""
    pytest.importorskip("msoffcrypto")
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")
    pytest.importorskip("cryptography")
    cert_pem, key_pem = make_self_signed_pem(tmp_path)
    out = tmp_path / "dec_signed.xlsx"
    result = unlock_document(
        enc,
        out,
        UnlockOptions(
            password="Password1234_",
            resign_cert=cert_pem,
            resign_key=key_pem,
        ),
    )
    assert out.is_file()
    assert any("Re-signed" in w for w in result.warnings)
    with zipfile.ZipFile(out) as zf:
        assert any(n.startswith("_xmlsignatures/") for n in zf.namelist())


def test_suffix_fallback_inspect_note_has_no_legacy_binary_flag() -> None:
    """Suffix-only .xls note must not advertise removed --legacy-binary."""
    import tempfile

    from dietrich.crypto.detect import classify_path

    # Non-OLE bytes with .xls suffix hits suffix fallback in classify_path
    path = Path(tempfile.mkdtemp()) / "fake.xls"
    path.write_bytes(b"NOT_AN_OLE_FILE")
    inspection = classify_path(path)
    assert inspection.document_format == DocumentFormat.LEGACY_CFBF
    joined = " ".join(inspection.notes) + " ".join(inspection.strategies)
    assert "--legacy-binary" not in joined
    assert "soft:binary_protection" in inspection.strategies


def test_resign_with_self_signed_cert(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from dietrich.signatures.resign import resign_ooxml_package

    cert_pem, key_pem = make_self_signed_pem(tmp_path)

    pkg = tmp_path / "in.xlsx"
    write_ooxml(
        pkg,
        {
            "[Content_Types].xml": (
                b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
            ),
            "_rels/.rels": (
                b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'
            ),
            "xl/workbook.xml": b"<workbook/>",
        },
        compression=zipfile.ZIP_STORED,
    )

    resign_ooxml_package(pkg, pkg, cert_pem=cert_pem, key_pem=key_pem, overwrite=True)
    with zipfile.ZipFile(pkg) as z:
        names = z.namelist()
        assert any(n.startswith("_xmlsignatures/") for n in names)
        assert b"SignatureValue" in z.read("_xmlsignatures/sig1.xml")


def test_resign_publish_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed signed-package publish must not erase the previous destination."""
    pytest.importorskip("cryptography")
    from dietrich.signatures import resign

    cert_pem, key_pem = make_self_signed_pem(tmp_path)
    package = tmp_path / "in.xlsx"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("xl/workbook.xml", b"<workbook/>")
    output = tmp_path / "signed.xlsx"
    output.write_bytes(b"prior destination")

    def fail_publish(temp_path: Path, target_path: Path, *, overwrite: bool) -> None:
        assert temp_path.parent == output.parent
        assert temp_path != target_path
        assert zipfile.is_zipfile(temp_path)
        assert overwrite is True
        raise OSError("injected publication failure")

    monkeypatch.setattr(resign, "publish_output", fail_publish)

    with pytest.raises(OSError, match="injected publication failure"):
        resign.resign_ooxml_package(
            package,
            output,
            cert_pem=cert_pem,
            key_pem=key_pem,
            overwrite=True,
        )

    assert output.read_bytes() == b"prior destination"
    assert not list(tmp_path.glob(".signed.xlsx.*.tmp"))


def test_resign_publish_race_preserves_competing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination created during signing must win a no-overwrite race."""
    pytest.importorskip("cryptography")
    from dietrich.errors import OutputExistsError
    from dietrich.safety.publish import publish_output as real_publish_output
    from dietrich.signatures import resign

    cert_pem, key_pem = make_self_signed_pem(tmp_path)
    package = tmp_path / "in.xlsx"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("xl/workbook.xml", b"<workbook/>")
    output = tmp_path / "signed.xlsx"

    def race_publish(temp_path: Path, target_path: Path, *, overwrite: bool) -> None:
        target_path.write_bytes(b"competing destination")
        real_publish_output(temp_path, target_path, overwrite=overwrite)

    monkeypatch.setattr(resign, "publish_output", race_publish)

    with pytest.raises(OutputExistsError):
        resign.resign_ooxml_package(
            package,
            output,
            cert_pem=cert_pem,
            key_pem=key_pem,
        )

    assert output.read_bytes() == b"competing destination"
    assert not list(tmp_path.glob(".signed.xlsx.*.tmp"))


def test_cli_hashcat_flag_requires_hashcat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from dietrich.crypto import hashcat_runner
    from dietrich.errors import MissingDependencyError

    monkeypatch.setattr(
        hashcat_runner,
        "find_hashcat",
        lambda: (_ for _ in ()).throw(MissingDependencyError("hashcat not found")),
    )
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")
    with pytest.raises(MissingDependencyError):
        unlock_document(
            enc,
            tmp_path / "o.xlsx",
            UnlockOptions(use_hashcat=True, wordlist=tmp_path / "w.txt"),
        )
