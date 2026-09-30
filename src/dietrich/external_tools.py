"""Bounded, shell-free execution for local document-recovery tools."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import tempfile
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

from dietrich.operation import checkpoint

MAX_CAPTURE_BYTES = 1024 * 1024
PROCESS_GRACE_SECONDS = 0.2


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

    collection = asyncio.create_task(collect())
    try:
        returncode, stdout, stderr = await _wait_for_collection(collection, timeout)
    except BaseException:
        await _stop_process_tree(process)
        if not collection.done():
            collection.cancel()
        await asyncio.gather(collection, return_exceptions=True)
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


async def _wait_for_collection(
    collection: asyncio.Task[tuple[int, bytes, bytes]], timeout: float | None
) -> tuple[int, bytes, bytes]:
    """Poll the operation control while awaiting bounded process output."""
    loop = asyncio.get_running_loop()
    deadline = None if timeout is None else loop.time() + timeout
    while True:
        checkpoint()
        if deadline is not None and loop.time() >= deadline:
            raise TimeoutError
        interval = 0.05 if deadline is None else min(0.05, deadline - loop.time())
        done, _ = await asyncio.wait({collection}, timeout=max(0, interval))
        if collection in done:
            return await collection


async def run_hashcat_argv(
    argv: Sequence[str | PathLike[str]],
    *,
    timeout: float | None = None,
    cwd: str | PathLike[str] | None = None,
) -> ProcessResult:
    """Run a validated hashcat command in a private working directory."""
    checkpoint("running hashcat")
    if len(argv) < 2 or str(argv[1]) != "-m":
        raise ValueError("hashcat argv must begin with an executable followed by '-m'")
    process = await _create_process_safely(_create_hashcat_process(argv, cwd=cwd))
    result = await capture_process(process, timeout=timeout)
    checkpoint()
    return result


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
    checkpoint("running pdf2john")
    with tempfile.TemporaryDirectory(prefix="dietrich-pdf2john-") as directory:
        shutil.copyfile(source, Path(directory) / "input.pdf")
        checkpoint()
        process = await _create_process_safely(_create_pdf2john_process(executable, cwd=directory))
        result = await capture_process(process, timeout=timeout)
        checkpoint()
        return result


def run_pdf2john_sync(
    executable: str | PathLike[str], source: str | PathLike[str], *, timeout: float | None = None
) -> ProcessResult:
    """Run :func:`run_pdf2john` from the synchronous PDF recovery path."""
    return asyncio.run(run_pdf2john(executable, source, timeout=timeout))


async def _create_hashcat_process(
    argv: Sequence[str | PathLike[str]], *, cwd: str | PathLike[str] | None
) -> asyncio.subprocess.Process:
    executable = str(argv[0])
    arguments = tuple(str(argument) for argument in argv[2:])
    return await asyncio.create_subprocess_exec(
        executable,
        "-m",
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=_sanitized_environment(),
        start_new_session=True,
    )


async def _create_process_safely(
    creation: Coroutine[Any, Any, asyncio.subprocess.Process],
) -> asyncio.subprocess.Process:
    """Finish an in-flight spawn on caller cancellation so its child can be reaped."""
    task = asyncio.create_task(creation)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        process = await asyncio.shield(task)
        await _stop_process_tree(process)
        raise


async def _create_pdf2john_process(
    executable: str | PathLike[str], *, cwd: str | PathLike[str]
) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        str(executable),
        "input.pdf",
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


async def _stop_process_tree(process: asyncio.subprocess.Process) -> None:
    """Stop an isolated POSIX group or the direct Windows child, then reap it."""
    if os.name == "nt":
        if process.returncode is None:
            process.terminate()
        await _wait_grace(process)
        if process.returncode is None:
            process.kill()
        await process.wait()
        return

    _signal_process_group(process.pid, signal.SIGTERM)
    await asyncio.sleep(PROCESS_GRACE_SECONDS)
    _signal_process_group(process.pid, signal.SIGKILL)
    await process.wait()


async def _wait_grace(process: asyncio.subprocess.Process) -> None:
    """Give a directly managed child a short cooperative shutdown window."""
    deadline = asyncio.get_running_loop().time() + PROCESS_GRACE_SECONDS
    while process.returncode is None and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(0.01)


def _signal_process_group(pid: int, signal_number: signal.Signals) -> None:
    """Signal a child-created POSIX session, tolerating an already-dead group."""
    try:
        os.killpg(pid, signal_number)
    except ProcessLookupError:
        pass


__all__ = [
    "MAX_CAPTURE_BYTES",
    "PROCESS_GRACE_SECONDS",
    "ProcessOutputLimitError",
    "ProcessResult",
    "capture_process",
    "run_hashcat_argv_sync",
    "run_pdf2john_sync",
]
