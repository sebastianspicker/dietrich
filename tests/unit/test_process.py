"""Tests for the shell-free child-process runner."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from dietrich.process import ProcessResult, run_hashcat_argv, run_pdf2john


def test_run_hashcat_argv_captures_text_and_returncode() -> None:
    result = asyncio.run(run_hashcat_argv([sys.executable, "-m", "this"]))

    assert result.returncode == 0
    assert "Beautiful" in result.stdout
    assert result.stderr == ""


def test_run_hashcat_argv_kills_and_reaps_timed_out_child() -> None:
    with pytest.raises(TimeoutError):
        asyncio.run(
            run_hashcat_argv(
                [sys.executable, "-m", "timeit", "-n", "1", "import time; time.sleep(60)"],
                timeout=0.1,
            )
        )


def test_run_pdf2john_uses_fixed_input_alias(tmp_path: Path) -> None:
    source = tmp_path / "untrusted filename.pdf"
    source.write_text("PDF sample", encoding="utf-8")
    executable = tmp_path / "fake_pdf2john"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1] == 'input.pdf'\n"
        "assert Path('input.pdf').read_text(encoding='utf-8') == 'PDF sample'\n"
        "print(sys.argv[1])\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = asyncio.run(run_pdf2john(executable, source))

    assert result == ProcessResult(returncode=0, stdout="input.pdf\n", stderr="")
