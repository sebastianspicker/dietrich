"""Encrypted Office password verification, hash export, and metadata tests."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

msoffcrypto = pytest.importorskip("msoffcrypto")

from dietrich import UnlockOptions, inspect_document, unlock_document  # noqa: E402
from dietrich.crypto.attack import run_file_attack  # noqa: E402
from dietrich.crypto.ooxml_crypto import (  # noqa: E402
    describe_encryption,
    export_hash_line,
    try_password,
)
from dietrich.types import AttackOptions, DocumentFormat  # noqa: E402
from tests.support.fixtures import ENCRYPTED_XLSX, KNOWN_PASSWORD  # noqa: E402

# Ground truth from openwall office2john.py on the same fixture.
OFFICE2JOHN_HASHCAT_BODY = (
    "$office$201310000025616*"
    "69035a89b22ce6d55eec2034d35821ba*"
    "e846343475cb215c1e0b1880601c1dbc*"
    "3535172cb015061586d7ad55edb1a104760056e5e49f500099a36e903ffc87fb"
)

pytestmark = pytest.mark.skipif(
    not ENCRYPTED_XLSX.is_file(),
    reason="encrypted fixture missing",
)


def test_export_hash_matches_office2john() -> None:
    line = export_hash_line(ENCRYPTED_XLSX, fmt="hashcat")
    assert line == OFFICE2JOHN_HASHCAT_BODY

    john = export_hash_line(ENCRYPTED_XLSX, fmt="john")
    assert john == f"example_password.xlsx:{OFFICE2JOHN_HASHCAT_BODY}"


def test_cli_export_hash_subprocess() -> None:
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(
        [sys.executable, "-m", "dietrich", str(ENCRYPTED_XLSX), "--export-hash", "hashcat"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == OFFICE2JOHN_HASHCAT_BODY


def test_describe_encryption_agile_expensive() -> None:
    meta = describe_encryption(ENCRYPTED_XLSX)
    assert meta.scheme == "agile"
    assert meta.version_label == "2013"
    assert meta.spin_count == 100_000
    assert meta.cost_class == "expensive"
    assert meta.hashcat_mode == 9600


def test_inspect_includes_hard_metadata() -> None:
    inspection = inspect_document(ENCRYPTED_XLSX)
    assert inspection.document_format == DocumentFormat.ENCRYPTED_OOXML
    assert inspection.encryption_scheme == "agile"
    assert inspection.encryption_version == "2013"
    assert inspection.encryption_spin_count == 100_000
    assert inspection.hashcat_mode == 9600
    assert inspection.encryption_cost_class == "expensive"


def test_try_password_verify_only_is_fast() -> None:
    # Warm-up
    assert try_password(ENCRYPTED_XLSX, KNOWN_PASSWORD) is True
    assert try_password(ENCRYPTED_XLSX, "wrong") is False

    start = time.perf_counter()
    n = 5
    for _ in range(n):
        assert try_password(ENCRYPTED_XLSX, "wrong-password-xyz") is False
    elapsed = time.perf_counter() - start
    # 5 wrong verifies with spin=100k should complete well under a full minute
    # and each attempt must not do a full package decrypt.
    assert elapsed < 60.0


def test_parallel_wordlist_finds_password(tmp_path: Path) -> None:
    wl = tmp_path / "w.txt"
    # Several decoys then the real password
    wl.write_text("aaa\nbbb\nccc\nPassword1234_\n", encoding="utf-8")
    result = run_file_attack(
        ENCRYPTED_XLSX,
        AttackOptions(wordlist=wl, try_empty=False, workers=2),
        kind="ooxml",
    )
    assert result.success
    assert result.password == KNOWN_PASSWORD


def test_unlock_still_works_after_hard_path_changes(tmp_path: Path) -> None:
    out = tmp_path / "out.xlsx"
    result = unlock_document(
        ENCRYPTED_XLSX,
        out,
        UnlockOptions(password=KNOWN_PASSWORD),
    )
    assert out.is_file()
    assert result.password_used == KNOWN_PASSWORD
