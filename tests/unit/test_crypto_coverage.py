"""Unit contracts for crypto metadata, optional dependencies, and hashcat outcomes."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from dietrich.crypto import hashcat_runner, ooxml_crypto, pdf_crypto
from dietrich.errors import (
    EncryptedDocumentError,
    MissingDependencyError,
    PasswordNotFoundError,
)
from dietrich.process import ProcessResult


class _Office:
    """Minimal OfficeFile double for metadata-only classification."""

    def __init__(self, encrypted: bool, scheme: str | None, info: dict[object, object]) -> None:
        self.encrypted = encrypted
        self.type = scheme
        self.info = info

    def is_encrypted(self) -> bool:
        return self.encrypted


@pytest.mark.parametrize(
    ("office", "expected"),
    [
        (
            _Office(
                True,
                "agile",
                {
                    "passwordHashAlgorithm": "SHA1",
                    "passwordKeyBits": 128,
                    "spinValue": 50_000,
                    "passwordSalt": b"salt",
                },
            ),
            ("agile", "2010", 9500, "moderate", 4, ()),
        ),
        (
            _Office(True, "agile", {"passwordHashAlgorithm": "SHA256"}),
            ("agile", "agile", None, "moderate", None, ("Unsupported hash algorithm",)),
        ),
        (
            _Office(True, "standard", {}),
            ("standard", "2007", 9400, "moderate", 16, ("Standard ECMA-376",)),
        ),
        (
            _Office(True, "rc4", {}),
            ("rc4", "rc4", None, "trivial", None, ("Legacy weak scheme",)),
        ),
    ],
)
def test_describe_encryption_classifies_supported_and_legacy_schemes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    office: _Office,
    expected: tuple[str, str, int | None, str, int | None, tuple[str, ...]],
) -> None:
    """Metadata stays useful even where a scheme cannot be exported to hashcat."""
    closed: list[_Office] = []
    monkeypatch.setattr(ooxml_crypto, "open_office", lambda _path: office)
    monkeypatch.setattr(ooxml_crypto, "close_office", closed.append)

    metadata = ooxml_crypto.describe_encryption(tmp_path / "sample.docx")

    scheme, version, mode, cost, salt_size, note_prefixes = expected
    assert (metadata.scheme, metadata.version_label, metadata.hashcat_mode) == (
        scheme,
        version,
        mode,
    )
    assert (metadata.cost_class, metadata.salt_size) == (cost, salt_size)
    assert all(any(note.startswith(prefix) for note in metadata.notes) for prefix in note_prefixes)
    assert closed == [office]


def test_describe_encryption_identifies_unencrypted_office_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    office = _Office(False, None, {})
    monkeypatch.setattr(ooxml_crypto, "open_office", lambda _path: office)
    monkeypatch.setattr(ooxml_crypto, "close_office", lambda _office: None)

    metadata = ooxml_crypto.describe_encryption(tmp_path / "plain.xlsx")

    assert metadata.scheme == "none"
    assert metadata.cost_class == "none"
    assert metadata.notes == ("File is not open-password encrypted.",)


def test_ooxml_crypto_reports_missing_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "msoffcrypto", None)

    with pytest.raises(MissingDependencyError, match=r"dietrich\[crypto\]"):
        ooxml_crypto._require_msoffcrypto()


def test_pdf_crypto_reports_missing_optional_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pikepdf", None)

    with pytest.raises(MissingDependencyError, match=r"dietrich\[pdf\]"):
        pdf_crypto._require_pikepdf()


def test_pdf_try_password_returns_false_for_malformed_document(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakePdfError(Exception):
        pass

    fake_pikepdf = SimpleNamespace(
        PasswordError=type("PasswordError", (Exception,), {}),
        PdfError=FakePdfError,
        open=lambda *_args, **_kwargs: (_ for _ in ()).throw(FakePdfError("bad trailer")),
    )
    monkeypatch.setattr(pdf_crypto, "_require_pikepdf", lambda: fake_pikepdf)

    assert pdf_crypto.try_password(tmp_path / "broken.pdf", "secret") is False


def test_pdf_decrypt_translates_incorrect_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    password_error = type("PasswordError", (Exception,), {})
    fake_pikepdf = SimpleNamespace(
        PasswordError=password_error,
        PdfError=type("PdfError", (Exception,), {}),
        open=lambda *_args, **_kwargs: (_ for _ in ()).throw(password_error("bad password")),
    )
    monkeypatch.setattr(pdf_crypto, "_require_pikepdf", lambda: fake_pikepdf)

    with pytest.raises(EncryptedDocumentError, match="incorrect password"):
        pdf_crypto.decrypt_to(tmp_path / "locked.pdf", "wrong", tmp_path / "out.pdf")


def test_pdf_hash_export_uses_pdf2john_when_native_parser_rejects_document(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "locked.pdf"
    source.write_bytes(b"%PDF-1.7\n")
    monkeypatch.setattr(
        pdf_crypto,
        "_native_hash_line",
        lambda _path, _fmt: (_ for _ in ()).throw(
            EncryptedDocumentError("unsupported native form")
        ),
    )
    monkeypatch.setattr(pdf_crypto, "_pdf2john_hash_line", lambda _path, _fmt: "$pdf$5*6*fallback")

    assert pdf_crypto.export_hash_line(source) == "$pdf$5*6*fallback"


def test_hashcat_wordlist_command_returns_plaintext_outfile_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("candidate\n", encoding="utf-8")
    captured: list[tuple[list[str], int | None]] = []

    def fake_run(command: list[str], *, timeout: int | None) -> ProcessResult:
        captured.append((command, timeout))
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text("recovered-password\n", encoding="utf-8")
        return ProcessResult(returncode=0, stdout="Recovered", stderr="")

    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/tools/hashcat")
    monkeypatch.setattr(hashcat_runner, "run_hashcat_argv_sync", fake_run)

    result = hashcat_runner.run_hashcat_for_office(
        "input.xlsx:$office$201310000025616*salt*verifier",
        mode=9600,
        wordlist=wordlist,
        workload="3",
        timeout=30,
    )

    command, timeout = captured[0]
    assert command[:7] == ["/tools/hashcat", "-m", "9600", "-a", "0", "-w", "3"]
    assert command[-1] == str(wordlist)
    assert timeout == 30
    assert result.success is True
    assert result.password == "recovered-password"
    assert result.message == "password found via hashcat"


def test_hashcat_timeout_and_launch_errors_are_user_facing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/tools/hashcat")

    def timed_out(_command: list[str], *, timeout: int | None) -> ProcessResult:
        assert timeout == 5
        raise TimeoutError

    monkeypatch.setattr(hashcat_runner, "run_hashcat_argv_sync", timed_out)
    with pytest.raises(PasswordNotFoundError, match="timed out after 5s"):
        hashcat_runner.run_hashcat_for_office("$office$2013example", mode=9600, timeout=5)

    def cannot_launch(_command: list[str], *, timeout: int | None) -> ProcessResult:
        raise OSError("execution denied")

    monkeypatch.setattr(hashcat_runner, "run_hashcat_argv_sync", cannot_launch)
    with pytest.raises(MissingDependencyError, match="failed to execute hashcat"):
        hashcat_runner.run_hashcat_for_office("$office$2013example", mode=9600)
