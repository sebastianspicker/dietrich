"""Focused contracts for local file attacks and the hashcat command wrapper."""

from __future__ import annotations

from pathlib import Path

import pytest

from dietrich.crypto import attack, hashcat_runner
from dietrich.crypto.hashcat_runner import run_hashcat_for_office
from dietrich.errors import EncryptedDocumentError
from dietrich.process import ProcessResult
from dietrich.types import AttackOptions


def test_file_attack_passes_path_and_password_to_file_worker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The file-specific worker receives its tuple input, unlike VerifierFn."""
    received: list[tuple[str, str]] = []

    def worker(args: tuple[str, str]) -> str | None:
        received.append(args)
        return args[1] if args[1] == "open-sesame" else None

    monkeypatch.setattr(attack, "_try_ooxml_password", worker)

    source = tmp_path / "encrypted.xlsx"
    result = attack.run_file_attack(
        source,
        AttackOptions(passwords=("incorrect", "open-sesame"), try_empty=False),
    )

    assert result.success is True
    assert result.password == "open-sesame"
    assert result.candidates_tried == 2
    assert received == [(str(source), "incorrect"), (str(source), "open-sesame")]


def test_hashcat_mask_command_preserves_public_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public arguments still yield the same controlled mask command."""
    captured: list[tuple[list[str], int | None]] = []

    def fake_run(command: list[str], *, timeout: int | None) -> ProcessResult:
        captured.append((command, timeout))
        return ProcessResult(returncode=1, stdout="out", stderr="err")

    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/usr/bin/hashcat")
    monkeypatch.setattr(hashcat_runner, "run_hashcat_argv_sync", fake_run)

    result = run_hashcat_for_office(
        "$office$201310000025616*salt*verifier",
        mode=9600,
        mask="?d?d",
        extra_args=["--quiet"],
        workload="4",
        timeout=12,
    )

    command, timeout = captured[0]
    assert command[:8] == ["/usr/bin/hashcat", "-m", "9600", "-a", "3", "-w", "4", "--potfile-path"]
    assert command[-2:] == ["?d?d", "--quiet"]
    assert timeout == 12
    assert result.success is False
    assert result.mode == 9600
    assert result.stdout_tail == "out\nerr"


def test_hashcat_rejects_wordlist_and_mask_together(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The refactor retains the mutually-exclusive attack-material error."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/usr/bin/hashcat")

    with pytest.raises(EncryptedDocumentError, match="either --wordlist or --mask"):
        run_hashcat_for_office(
            "$office$201310000025616*salt*verifier",
            mode=9600,
            wordlist=wordlist,
            mask="?d",
        )
