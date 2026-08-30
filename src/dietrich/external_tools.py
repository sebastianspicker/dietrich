"""Bounded, shell-free execution for local document-recovery tools."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from pathlib import Path

MAX_CAPTURE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ProcessResult:
    """Bounded result of an argv-only child-process invocation."""

    returncode: int
    stdout: str
    stderr: str


async def capture_process(
    process: asyncio.subprocess.Process,
    *,
    timeout: float | None = None,
    capture_limit: int = MAX_CAPTURE_BYTES,
) -> ProcessResult:
    """Capture bounded output, terminating and reaping on timeout or overflow."""

    async def collect() -> tuple[int, bytes, bytes]:
        tasks = [
            asyncio.create_task(process.wait()),
            asyncio.create_task(_read_limited(process.stdout, capture_limit)),
            asyncio.create_task(_read_limited(process.stderr, capture_limit)),
        ]
        try:
            results = await asyncio.gather(*tasks)
            return int(results[0]), bytes(results[1]), bytes(results[2])
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        returncode, stdout, stderr = await asyncio.wait_for(collect(), timeout)
    except (TimeoutError, ProcessOutputLimitError):
        if process.returncode is None:
            _kill_process_group(process)
        await process.wait()
        raise
    return ProcessResult(
        returncode=returncode,
        stdout=stdout.decode(errors="replace"),
        stderr=stderr.decode(errors="replace"),
    )


class ProcessOutputLimitError(RuntimeError):
    """Raised when a child exceeds the configured captured-output budget."""


async def _read_limited(stream: asyncio.StreamReader | None, limit: int) -> bytes:
    if stream is None:
        return b""
    chunks: list[bytes] = []
    total = 0
    while chunk := await stream.read(64 * 1024):
        total += len(chunk)
        if total > limit:
            raise ProcessOutputLimitError(f"child process output exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


async def run_hashcat_argv(
    argv: Sequence[str | PathLike[str]],
    *,
    timeout: float | None = None,
    cwd: str | PathLike[str] | None = None,
) -> ProcessResult:
    """Run a validated hashcat command in a private working directory."""
    if len(argv) < 2 or str(argv[1]) != "-m":
        raise ValueError("hashcat argv must begin with an executable followed by '-m'")
    process = await _create_process(argv, cwd=cwd)
    return await capture_process(process, timeout=timeout)


def run_hashcat_argv_sync(
    argv: Sequence[str | PathLike[str]],
    *,
    timeout: float | None = None,
    cwd: str | PathLike[str] | None = None,
) -> ProcessResult:
    """Run :func:`run_hashcat_argv` from the synchronous application path."""
    return asyncio.run(run_hashcat_argv(argv, timeout=timeout, cwd=cwd))


async def run_pdf2john(
    executable: str | PathLike[str], source: str | PathLike[str], *, timeout: float | None = None
) -> ProcessResult:
    """Run pdf2john against a fixed private filename rather than user input."""
    with tempfile.TemporaryDirectory(prefix="dietrich-pdf2john-") as directory:
        shutil.copyfile(source, Path(directory) / "input.pdf")
        process = await _create_process((executable, "input.pdf"), cwd=directory)
        return await capture_process(process, timeout=timeout)


def run_pdf2john_sync(
    executable: str | PathLike[str], source: str | PathLike[str], *, timeout: float | None = None
) -> ProcessResult:
    """Run :func:`run_pdf2john` from the synchronous PDF recovery path."""
    return asyncio.run(run_pdf2john(executable, source, timeout=timeout))


async def _create_process(
    argv: Sequence[str | PathLike[str]], *, cwd: str | PathLike[str] | None
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *(str(argument) for argument in argv),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=_sanitized_environment(),
        start_new_session=True,
    )


def _sanitized_environment() -> Mapping[str, str]:
    """Pass only execution and locale variables, never unrelated process secrets."""
    return {
        key: value
        for key in ("PATH", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
        if (value := os.environ.get(key)) is not None
    }


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    """Terminate the isolated tool process and any children it created."""
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    process.kill()


__all__ = [
    "MAX_CAPTURE_BYTES",
    "ProcessOutputLimitError",
    "ProcessResult",
    "capture_process",
    "run_hashcat_argv_sync",
    "run_pdf2john_sync",
]
