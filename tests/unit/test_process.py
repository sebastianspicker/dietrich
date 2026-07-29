"""Tests for the shell-free child-process runner."""

from __future__ import annotations

import asyncio
import sys

import pytest

from dietrich.process import ProcessResult, run_argv


def test_run_argv_captures_text_and_returncode() -> None:
    result = asyncio.run(
        run_argv(
            [
                sys.executable,
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr); raise SystemExit(7)",
            ]
        )
    )

    assert result == ProcessResult(returncode=7, stdout="out\n", stderr="err\n")


def test_run_argv_kills_and_reaps_timed_out_child() -> None:
    with pytest.raises(TimeoutError):
        asyncio.run(run_argv([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.1))
