"""Password candidate generation and parallel verification orchestration.

Builds candidates from wordlists, masks, and charsets; verifies via callbacks
or process-pool workers without implementing document crypto itself.
"""

from __future__ import annotations

import itertools
import string
from collections.abc import Callable, Iterator
from concurrent.futures import CancelledError, ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path

from dietrich.errors import EncryptedDocumentError
from dietrich.types import AttackOptions, AttackResult

VerifierFn = Callable[[str], bool]
FileAttackWorker = Callable[[tuple[str, str]], str | None]

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
    """Yield unique password candidates under AttackOptions caps."""
    seen: set[str] = set()
    for password in _candidate_sources(options):
        if password in seen:
            continue
        seen.add(password)
        yield password
        if len(seen) >= options.max_candidates:
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


def run_attack(verifier: VerifierFn, options: AttackOptions) -> AttackResult:
    """Serial attack using an in-process verifier callback."""
    tried = 0
    for password in iter_candidates(options):
        tried += 1
        try:
            if verifier(password):
                return AttackResult(
                    success=True,
                    password=password,
                    candidates_tried=tried,
                    message="password found",
                )
        except (EncryptedDocumentError, OSError, RuntimeError, TypeError, ValueError):
            continue
    return AttackResult(
        success=False,
        password=None,
        candidates_tried=tried,
        message="password not found in candidate set",
    )


def _try_ooxml_password(args: tuple[str, str]) -> str | None:
    """Process-pool worker: (path, password) → password if valid."""
    path_str, password = args
    from dietrich.crypto.ooxml_crypto import try_password

    try:
        if try_password(Path(path_str), password):
            return password
    except (EncryptedDocumentError, OSError, RuntimeError, TypeError, ValueError):
        return None
    return None


def _try_pdf_password(args: tuple[str, str]) -> str | None:
    """Return True if pikepdf accepts this password for the path."""
    path_str, password = args
    from dietrich.crypto.pdf_crypto import try_password

    try:
        if try_password(Path(path_str), password):
            return password
    except (EncryptedDocumentError, OSError, RuntimeError, TypeError, ValueError):
        return None
    return None


def run_file_attack(
    path: Path,
    options: AttackOptions,
    *,
    kind: str = "ooxml",
) -> AttackResult:
    """Attack an encrypted file; parallelize when workers > 1."""
    path = Path(path)
    worker = _try_ooxml_password if kind == "ooxml" else _try_pdf_password
    candidates = list(iter_candidates(options))
    if not candidates:
        return _attack_not_found(0)

    if options.workers <= 1:
        return _run_serial_file_attack(path, candidates, worker)
    return _run_parallel_file_attack(path, candidates, worker, options.workers)


def _run_serial_file_attack(
    path: Path, candidates: list[str], worker: FileAttackWorker
) -> AttackResult:
    """Try candidate passwords in order without creating child processes."""
    for tried, password in enumerate(candidates, start=1):
        found = worker((str(path), password))
        if found is not None:
            return _attack_found(found, tried)
    return _attack_not_found(len(candidates))


def _run_parallel_file_attack(
    path: Path, candidates: list[str], worker: FileAttackWorker, workers: int
) -> AttackResult:
    """Submit independent candidates and cancel pending work after a match."""
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(worker, (str(path), password)): password for password in candidates}
        for tried, future in enumerate(as_completed(futures), start=1):
            try:
                result = future.result()
            except (
                BrokenProcessPool,
                CancelledError,
                EncryptedDocumentError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ):
                result = None
            if result is not None:
                for pending in futures:
                    pending.cancel()
                return _attack_found(result, tried)
    return _attack_not_found(len(candidates))


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
