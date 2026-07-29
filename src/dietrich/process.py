"""Minimal shell-free process execution helpers."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from os import PathLike
from pathlib import Path


@dataclass(frozen=True)
class ProcessResult:
    """Captured result of an argv-only child process invocation."""

    returncode: int
    stdout: str
    stderr: str


async def capture_process(
    process: asyncio.subprocess.Process, *, timeout: float | None = None
) -> ProcessResult:
    """Capture a child process, killing and reaping it if its timeout expires."""
    try:
        if timeout is None:
            stdout, stderr = await process.communicate()
        else:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        raise
    if process.returncode is None:
        raise RuntimeError("child process completed without a return code")
    return ProcessResult(
        returncode=process.returncode,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


async def run_hashcat_argv(
    argv: Sequence[str | PathLike[str]], *, timeout: float | None = None
) -> ProcessResult:
    """Run a validated hashcat command with its literal ``-m`` argument."""
    if len(argv) < 2 or str(argv[1]) != "-m":
        raise ValueError("hashcat argv must begin with an executable followed by '-m'")
    process = await asyncio.create_subprocess_exec(
        str(argv[0]),
        "-m",
        *(str(argument) for argument in argv[2:]),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    return await capture_process(process, timeout=timeout)


def run_hashcat_argv_sync(
    argv: Sequence[str | PathLike[str]], *, timeout: float | None = None
) -> ProcessResult:
    """Run :func:`run_hashcat_argv` from the synchronous crypto call path."""
    return asyncio.run(run_hashcat_argv(argv, timeout=timeout))


async def run_pdf2john(
    executable: str | PathLike[str], source: str | PathLike[str], *, timeout: float | None = None
) -> ProcessResult:
    """Run pdf2john against a fixed temporary filename rather than user input."""
    with tempfile.TemporaryDirectory(prefix="dietrich-pdf2john-") as directory:
        shutil.copyfile(source, Path(directory) / "input.pdf")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "input.pdf",
            cwd=directory,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return await capture_process(process, timeout=timeout)


def run_pdf2john_sync(
    executable: str | PathLike[str], source: str | PathLike[str], *, timeout: float | None = None
) -> ProcessResult:
    """Run :func:`run_pdf2john` from the synchronous PDF hash-export path."""
    return asyncio.run(run_pdf2john(executable, source, timeout=timeout))
