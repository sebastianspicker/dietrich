"""Minimal shell-free process execution helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass
from os import PathLike


@dataclass(frozen=True)
class ProcessResult:
    """Captured result of an argv-only child process invocation."""

    returncode: int
    stdout: str
    stderr: str


async def run_argv(
    argv: Sequence[str | PathLike[str]], *, timeout: float | None = None
) -> ProcessResult:
    """Run argv without a shell, capturing text and reaping timed-out children."""
    process = await asyncio.create_subprocess_exec(
        *(str(argument) for argument in argv),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
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


def run_argv_sync(
    argv: Sequence[str | PathLike[str]], *, timeout: float | None = None
) -> ProcessResult:
    """Run :func:`run_argv` from the synchronous crypto call paths."""
    return asyncio.run(run_argv(argv, timeout=timeout))
