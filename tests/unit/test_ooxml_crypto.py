"""Focused Office decryption error-contract tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

msoffcrypto = pytest.importorskip("msoffcrypto")

from dietrich.crypto import ooxml_crypto  # noqa: E402
from dietrich.errors import EncryptedDocumentError  # noqa: E402


class _FailingOffice:
    """Minimal msoffcrypto stand-in that fails during payload decryption."""

    def is_encrypted(self) -> bool:
        return True

    def load_key(self, **_kwargs: Any) -> None:
        return None

    def decrypt(self, _output: Any) -> None:
        raise msoffcrypto.exceptions.DecryptionError("invalid decrypted payload")


class _MalformedHashOffice:
    """Agile document missing required EncryptionInfo fields."""

    type = "agile"
    info: dict[str, object] = {"passwordHashAlgorithm": "SHA512"}

    def is_encrypted(self) -> bool:
        return True


def test_decrypt_to_translates_msoffcrypto_decryption_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _FailingOffice()
    monkeypatch.setattr(ooxml_crypto, "open_office", lambda _path: office)
    monkeypatch.setattr(ooxml_crypto, "close_office", lambda _office: None)

    with pytest.raises(EncryptedDocumentError, match="decrypt failed"):
        ooxml_crypto.decrypt_to(tmp_path / "encrypted.xlsx", "secret", tmp_path / "out.xlsx")


def test_export_hash_translates_msoffcrypto_parser_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_open(_path: Path) -> Any:
        raise msoffcrypto.exceptions.FileFormatError("broken container")

    monkeypatch.setattr(ooxml_crypto, "open_office", fail_open)

    with pytest.raises(EncryptedDocumentError, match="could not export Office hash"):
        ooxml_crypto.export_hash_line(tmp_path / "broken.xlsx")


def test_export_hash_translates_malformed_agile_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    office = _MalformedHashOffice()
    closed: list[object] = []
    monkeypatch.setattr(ooxml_crypto, "open_office", lambda _path: office)
    monkeypatch.setattr(ooxml_crypto, "close_office", closed.append)

    with pytest.raises(EncryptedDocumentError, match="could not export Office hash"):
        ooxml_crypto.export_hash_line(tmp_path / "malformed.xlsx")

    assert closed == [office]
