"""Open-password recovery against encrypted Office fixtures."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

msoffcrypto = pytest.importorskip("msoffcrypto")

from dietrich import (  # noqa: E402
    EncryptedDocumentError,
    PasswordNotFoundError,
    UnlockOptions,
    inspect_document,
    unlock_document,
)
from dietrich.types import DocumentFormat  # noqa: E402
from tests.support.fixtures import (  # noqa: E402
    ENCRYPTED_DOCX,
    ENCRYPTED_XLSX,
    KNOWN_PASSWORD,
)

pytestmark = pytest.mark.skipif(
    not ENCRYPTED_XLSX.is_file(),
    reason="encrypted fixture missing under tests/fixtures/",
)


def test_inspect_classifies_encrypted_xlsx() -> None:
    inspection = inspect_document(ENCRYPTED_XLSX)
    assert inspection.document_format == DocumentFormat.ENCRYPTED_OOXML
    assert inspection.encrypted is True
    assert inspection.user_password_required is True
    assert any("password" in s or "wordlist" in s for s in inspection.strategies)


def test_unlock_with_explicit_password(tmp_path: Path) -> None:
    out = tmp_path / "unlocked.xlsx"
    result = unlock_document(
        ENCRYPTED_XLSX,
        out,
        UnlockOptions(password=KNOWN_PASSWORD),
    )
    assert out.is_file()
    assert result.password_used == KNOWN_PASSWORD
    assert any("Decrypted" in w for w in result.warnings)
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert any(n.startswith("xl/") for n in names)
        assert "EncryptionInfo" not in names
        assert "EncryptedPackage" not in names


def test_unlock_with_wordlist(tmp_path: Path) -> None:
    wordlist = tmp_path / "passwords.txt"
    wordlist.write_text("not-it\nPassword1234_\n", encoding="utf-8")
    out = tmp_path / "from_list.xlsx"
    result = unlock_document(
        ENCRYPTED_XLSX,
        out,
        UnlockOptions(wordlist=wordlist),
    )
    assert out.is_file()
    assert result.password_used == KNOWN_PASSWORD
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None


def test_wrong_password_fails_without_output(tmp_path: Path) -> None:
    out = tmp_path / "should_not_exist.xlsx"
    with pytest.raises(EncryptedDocumentError, match="incorrect"):
        unlock_document(ENCRYPTED_XLSX, out, UnlockOptions(password="wrong-password"))
    assert not out.exists()


def test_nonzip_decrypt_publish_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed binary publication must leave the prior output intact."""
    from dietrich import dispatch
    from dietrich.crypto import ooxml_crypto
    from dietrich.legacy import cfb_io

    source = tmp_path / "encrypted.doc"
    source.write_bytes(b"encrypted source")
    target = tmp_path / "unlocked.doc"
    target.write_bytes(b"prior destination")

    monkeypatch.setattr(dispatch, "_recover_password_ooxml", lambda *_args: "known-password")
    monkeypatch.setattr(
        ooxml_crypto,
        "decrypt_to",
        lambda _source, _password, destination: destination.write_bytes(
            cfb_io.CFBF_MAGIC + b"decrypted binary payload"
        ),
    )
    monkeypatch.setattr(cfb_io, "validate_cfb", lambda _path: None)
    prefix_limits: list[int] = []
    real_read_file_prefix = dispatch.read_file_prefix

    def read_prefix(path: Path, limit: int) -> bytes:
        prefix_limits.append(limit)
        return real_read_file_prefix(path, limit)

    monkeypatch.setattr(dispatch, "read_file_prefix", read_prefix)

    def fail_publish(temp_path: Path, target_path: Path, *, overwrite: bool) -> None:
        assert temp_path.parent == target.parent
        assert temp_path != target_path
        assert overwrite is True
        raise OSError("injected publication failure")

    monkeypatch.setattr(dispatch, "publish_output", fail_publish)

    with pytest.raises(OSError, match="injected publication failure"):
        dispatch._unlock_encrypted_office(source, target, UnlockOptions(overwrite=True))

    assert target.read_bytes() == b"prior destination"
    assert not list(tmp_path.glob(".unlocked.doc.*.tmp"))
    assert prefix_limits == [2, len(cfb_io.CFBF_MAGIC)]


def test_nonzip_decrypt_publish_race_preserves_competing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination created after the precheck must win a no-overwrite race."""
    from dietrich import dispatch
    from dietrich.crypto import ooxml_crypto
    from dietrich.errors import OutputExistsError
    from dietrich.legacy import cfb_io
    from dietrich.safety.publish import publish_output as real_publish_output

    source = tmp_path / "encrypted.doc"
    source.write_bytes(b"encrypted source")
    target = tmp_path / "unlocked.doc"
    monkeypatch.setattr(dispatch, "_recover_password_ooxml", lambda *_args: "known-password")
    monkeypatch.setattr(
        ooxml_crypto,
        "decrypt_to",
        lambda _source, _password, destination: destination.write_bytes(
            cfb_io.CFBF_MAGIC + b"decrypted binary payload"
        ),
    )
    monkeypatch.setattr(cfb_io, "validate_cfb", lambda _path: None)

    def race_publish(temp_path: Path, target_path: Path, *, overwrite: bool) -> None:
        target_path.write_bytes(b"competing destination")
        real_publish_output(temp_path, target_path, overwrite=overwrite)

    monkeypatch.setattr(dispatch, "publish_output", race_publish)

    with pytest.raises(OutputExistsError):
        dispatch._unlock_encrypted_office(source, target, UnlockOptions())

    assert target.read_bytes() == b"competing destination"
    assert not list(tmp_path.glob(".unlocked.doc.*.tmp"))


def test_exhausted_wordlist_fails_without_output(tmp_path: Path) -> None:
    wordlist = tmp_path / "empty_hits.txt"
    wordlist.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    out = tmp_path / "should_not_exist.xlsx"
    with pytest.raises(PasswordNotFoundError):
        unlock_document(ENCRYPTED_XLSX, out, UnlockOptions(wordlist=wordlist))
    assert not out.exists()


def test_soft_only_refuses_encrypted(tmp_path: Path) -> None:
    out = tmp_path / "nope.xlsx"
    with pytest.raises(EncryptedDocumentError, match="soft-only"):
        unlock_document(ENCRYPTED_XLSX, out, UnlockOptions(soft_only=True))
    assert not out.exists()


def test_decrypt_then_soft_unlock_pipeline_invoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure encrypted unlock always runs soft unlock on the decrypted package."""
    from dietrich import dispatch as dispatch_mod

    calls: list[Path] = []
    real = dispatch_mod.unlock_ooxml_package

    def wrapped(input_path, output_path, options):
        calls.append(Path(input_path))
        return real(input_path, output_path, options)

    monkeypatch.setattr(dispatch_mod, "unlock_ooxml_package", wrapped)
    out = tmp_path / "pipeline.xlsx"
    unlock_document(ENCRYPTED_XLSX, out, UnlockOptions(password=KNOWN_PASSWORD))
    assert calls, "soft unlock_ooxml_package was not called after decrypt"
    assert out.is_file()


def test_encrypted_docx_password_unlock(tmp_path: Path) -> None:
    if not ENCRYPTED_DOCX.is_file():
        pytest.skip("docx fixture missing")
    out = tmp_path / "unlocked.docx"
    result = unlock_document(
        ENCRYPTED_DOCX,
        out,
        UnlockOptions(password=KNOWN_PASSWORD),
    )
    assert out.is_file()
    assert result.password_used == KNOWN_PASSWORD
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None
        assert any(n.startswith("word/") for n in archive.namelist())


def test_soft_unlock_after_manual_decrypt_with_injected_protection(tmp_path: Path) -> None:
    """Decrypt fixture, inject sheetProtection, then soft-unlock via shipped API."""
    plain = tmp_path / "decrypted.xlsx"
    _decrypt_fixture(plain)

    protected = tmp_path / "protected.xlsx"
    _inject_ooxml_protection(plain, protected)

    out = tmp_path / "soft.xlsx"
    result = unlock_document(protected, out, UnlockOptions())
    assert result.removed.worksheet_protections >= 1
    assert result.removed.workbook_protections >= 1
    _assert_ooxml_protection_removed(out)


def _decrypt_fixture(destination: Path) -> None:
    """Decrypt the shared encrypted fixture into a temporary OOXML package."""
    with ENCRYPTED_XLSX.open("rb") as handle:
        office = msoffcrypto.OfficeFile(handle)
        office.load_key(password=KNOWN_PASSWORD)
        with destination.open("wb") as out:
            office.decrypt(out)


def _inject_ooxml_protection(plain: Path, protected: Path) -> None:
    """Add worksheet and workbook protection markers to an OOXML package."""
    with zipfile.ZipFile(plain, "r") as src, zipfile.ZipFile(protected, "w") as dst:
        for info in src.infolist():
            data = src.read(info)
            name = info.filename.replace("\\", "/")
            if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                if b"sheetProtection" not in data:
                    data = data.replace(
                        b"<sheetData",
                        b'<sheetProtection sheet="1"/><sheetData',
                        1,
                    )
            if name == "xl/workbook.xml" and b"workbookProtection" not in data:
                data = data.replace(
                    b"<sheets",
                    b'<workbookProtection lockStructure="1"/><sheets',
                    1,
                )
            dst.writestr(info, data)


def _assert_ooxml_protection_removed(path: Path) -> None:
    """Assert the soft unlock removed the markers injected for this integration test."""
    with zipfile.ZipFile(path) as archive:
        worksheet_names = [
            name
            for name in archive.namelist()
            if name.startswith("xl/worksheets/") and name.endswith(".xml")
        ]
        assert all(b"sheetProtection" not in archive.read(name) for name in worksheet_names)
        assert b"workbookProtection" not in archive.read("xl/workbook.xml")
