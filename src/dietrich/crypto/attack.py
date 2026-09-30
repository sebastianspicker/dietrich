"""Password candidate generation and explicitly owned worker orchestration."""

from __future__ import annotations

import itertools
import multiprocessing
import queue
import string
import time
from collections.abc import Callable, Iterator
from multiprocessing.managers import RemoteError, SyncManager
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import Any

from dietrich.domain.models import AttackOptions, AttackResult
from dietrich.errors import EncryptedDocumentError
from dietrich.operation import checkpoint

FileAttackWorker = Callable[[tuple[str, str]], str | None]

_EXPECTED_WORKER_ERRORS = (
    EncryptedDocumentError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)
_WORKER_GRACE_SECONDS = 0.2

CHARSETS: dict[str, str] = {
    "digits": string.digits,
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "alpha": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
    "printable": string.ascii_letters + string.digits + string.punctuation,
}


def expand_mask(mask: str) -> Iterator[str]:
    """Expand a simple hashcat-like mask: ?d ?l ?u ?a ?s and literals."""
    pools: list[list[str]] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            code = mask[i + 1]
            mapping = {
                "d": string.digits,
                "l": string.ascii_lowercase,
                "u": string.ascii_uppercase,
                "a": string.ascii_letters + string.digits,
                "s": string.punctuation,
            }
            if code == "?":
                pools.append(["?"])
            elif code in mapping:
                pools.append(list(mapping[code]))
            else:
                pools.append([code])
            i += 2
        else:
            pools.append([mask[i]])
            i += 1

    if not pools:
        return

    for combo in itertools.product(*pools):
        yield "".join(combo)


def iter_candidates(options: AttackOptions) -> Iterator[str]:
    """Stream password candidates under the configured attempt cap."""
    if options.max_candidates <= 0:
        return
    yielded = 0
    for password in _candidate_sources(options):
        yield password
        yielded += 1
        if yielded >= options.max_candidates:
            return


def _candidate_sources(options: AttackOptions) -> Iterator[str]:
    """Yield candidate sources in the documented priority order."""
    if options.try_empty:
        yield ""
    yield from options.passwords
    if options.wordlist is not None:
        yield from _wordlist_candidates(Path(options.wordlist))
    if options.mask:
        yield from expand_mask(options.mask)
    if options.charset and options.max_length is not None:
        yield from _charset_candidates(options.charset, options.max_length)


def _wordlist_candidates(path: Path) -> Iterator[str]:
    """Yield newline-normalized entries from an existing wordlist."""
    if not path.is_file():
        raise EncryptedDocumentError(f"wordlist not found: {path}")
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            yield line.rstrip("\n\r")


def _charset_candidates(charset: str, max_length: int) -> Iterator[str]:
    """Yield Cartesian-product candidates from a named or literal charset."""
    alphabet = CHARSETS.get(charset, charset)
    for length in range(1, max_length + 1):
        for combo in itertools.product(alphabet, repeat=length):
            yield "".join(combo)


def run_file_attack(
    path: Path,
    options: AttackOptions,
    *,
    worker: FileAttackWorker,
) -> AttackResult:
    """Attack an encrypted file with a format-owned, process-safe verifier."""
    checkpoint("recovering password")
    path = Path(path)
    candidates = iter_candidates(options)
    if options.workers <= 1:
        return _run_serial_file_attack(path, candidates, worker)
    return _run_parallel_file_attack(path, candidates, worker, options.workers)


def _run_serial_file_attack(
    path: Path, candidates: Iterator[str], worker: FileAttackWorker
) -> AttackResult:
    """Try candidate passwords in order without creating child processes."""
    tried = 0
    for tried, password in enumerate(candidates, start=1):
        checkpoint("recovering password")
        try:
            found = worker((str(path), password))
        except _EXPECTED_WORKER_ERRORS:
            found = None
        checkpoint()
        if found is not None:
            return _attack_found(found, tried)
    return _attack_not_found(tried)


def _run_parallel_file_attack(
    path: Path, candidates: Iterator[str], worker: FileAttackWorker, workers: int
) -> AttackResult:
    """Verify in spawn workers with a bounded candidate submission window."""
    context = multiprocessing.get_context("spawn")
    manager = SyncManager(ctx=context, shutdown_timeout=_WORKER_GRACE_SECONDS)
    manager.start()
    task_queue = None
    processes: list[BaseProcess] = []
    dispatched = 0
    outstanding = 0
    tried = 0
    exhausted = False
    try:
        task_queue = manager.Queue(maxsize=max(1, workers * 2))
        result_queue = manager.Queue()
        for identifier in range(max(1, workers)):
            checkpoint()
            processes.append(
                _start_worker(context, identifier, path, worker, task_queue, result_queue)
            )
        while True:
            checkpoint("recovering password")
            exhausted, dispatched, outstanding = _dispatch_candidates(
                task_queue,
                candidates,
                window=max(1, workers * 2),
                exhausted=exhausted,
                dispatched=dispatched,
                outstanding=outstanding,
            )
            if exhausted and outstanding == 0:
                return _attack_not_found(tried)

            try:
                _, status, password = result_queue.get(timeout=0.05)
            except queue.Empty:
                _raise_for_dead_worker(processes)
            else:
                outstanding -= 1
                tried += 1
                if status == "error":
                    raise RuntimeError(f"password worker failed: {password}")
                if password is not None:
                    return _attack_found(password, tried)
    finally:
        try:
            if task_queue is not None:
                _stop_workers(processes, task_queue)
        finally:
            manager.shutdown()


def _start_worker(
    context: Any,
    identifier: int,
    path: Path,
    worker: FileAttackWorker,
    task_queue: Any,
    result_queue: Any,
) -> BaseProcess:
    """Start one persistent spawn worker owned by the attack call."""
    process = context.Process(
        target=_worker_main,
        args=(str(path), worker, task_queue, result_queue),
        name=f"dietrich-password-{identifier}",
    )
    process.start()
    return process


def _worker_main(
    path: str,
    worker: FileAttackWorker,
    task_queue: Any,
    result_queue: Any,
) -> None:
    """Consume candidate tasks until the owner requests cooperative shutdown."""
    while (task := task_queue.get()) is not None:
        index, password = task
        try:
            result = worker((path, password))
        except _EXPECTED_WORKER_ERRORS:
            result_queue.put((index, "result", None))
        except BaseException as exc:
            result_queue.put((index, "error", f"{type(exc).__name__}: {exc}"))
            return
        else:
            result_queue.put((index, "result", result))


def _dispatch_candidates(
    task_queue: Any,
    candidates: Iterator[str],
    *,
    window: int,
    exhausted: bool,
    dispatched: int,
    outstanding: int,
) -> tuple[bool, int, int]:
    """Submit candidates in source order without blocking the owning process."""
    while not exhausted and outstanding < window:
        checkpoint()
        try:
            password = next(candidates)
        except StopIteration:
            exhausted = True
            break
        dispatched += 1
        task_queue.put_nowait((dispatched, password))
        outstanding += 1
    return exhausted, dispatched, outstanding


def _raise_for_dead_worker(processes: list[BaseProcess]) -> None:
    """Fail the attack if an owned worker exits outside cooperative shutdown."""
    for process in processes:
        if not process.is_alive():
            process.join()
            raise RuntimeError(f"password worker exited unexpectedly with code {process.exitcode}")


def _stop_workers(processes: list[BaseProcess], task_queue: Any) -> None:
    """Cooperatively stop, then terminate and kill every owned worker."""
    for _ in processes:
        try:
            task_queue.put_nowait(None)
        except (EOFError, OSError, RemoteError, queue.Full):
            break
    _join_until(processes, time.monotonic() + _WORKER_GRACE_SECONDS)
    for process in processes:
        if process.is_alive():
            process.terminate()
    _join_until(processes, time.monotonic() + _WORKER_GRACE_SECONDS)
    for process in processes:
        if process.is_alive():
            process.kill()
    for process in processes:
        process.join()


def _join_until(processes: list[BaseProcess], deadline: float) -> None:
    """Join each worker within one shared grace deadline."""
    for process in processes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        process.join(remaining)


def _attack_found(password: str, tried: int) -> AttackResult:
    """Create the shared successful-attack result."""
    return AttackResult(
        success=True,
        password=password,
        candidates_tried=tried,
        message="password found",
    )


def _attack_not_found(tried: int) -> AttackResult:
    """Create the shared exhausted-candidate result."""
    return AttackResult(
        success=False,
        password=None,
        candidates_tried=tried,
        message="password not found in candidate set",
    )
