"""Password candidate generation and parallel verification orchestration.

Builds candidates from wordlists, masks, and charsets; verifies via callbacks
or process-pool workers without implementing document crypto itself.
"""

from __future__ import annotations

import itertools
import string
from collections.abc import Callable, Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from dietrich.types import AttackOptions, AttackResult

VerifierFn = Callable[[str], bool]

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
    count = 0

    def consider(pw: str) -> str | None:
        """Deduplicate and cap; return pw once if still under max_candidates."""
        nonlocal count
        if pw in seen or count >= options.max_candidates:
            return None
        seen.add(pw)
        count += 1
        return pw

    if options.try_empty:
        item = consider("")
        if item is not None:
            yield item

    for pw in options.passwords:
        item = consider(pw)
        if item is not None:
            yield item
        if count >= options.max_candidates:
            return

    if options.wordlist is not None:
        path = Path(options.wordlist)
        if not path.is_file():
            from dietrich.errors import EncryptedDocumentError

            raise EncryptedDocumentError(f"wordlist not found: {path}")
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                item = consider(line.rstrip("\n\r"))
                if item is not None:
                    yield item
                if count >= options.max_candidates:
                    return

    if options.mask:
        for pw in expand_mask(options.mask):
            item = consider(pw)
            if item is not None:
                yield item
            if count >= options.max_candidates:
                return

    if options.charset and options.max_length is not None:
        alphabet = CHARSETS.get(options.charset, options.charset)
        for length in range(1, options.max_length + 1):
            for combo in itertools.product(alphabet, repeat=length):
                item = consider("".join(combo))
                if item is not None:
                    yield item
                if count >= options.max_candidates:
                    return


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
        except Exception:
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
    except Exception:
        return None
    return None


def _try_pdf_password(args: tuple[str, str]) -> str | None:
    """Return True if pikepdf accepts this password for the path."""
    path_str, password = args
    from dietrich.crypto.pdf_crypto import try_password

    try:
        if try_password(Path(path_str), password):
            return password
    except Exception:
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
        return AttackResult(
            success=False,
            password=None,
            candidates_tried=0,
            message="password not found in candidate set",
        )

    if options.workers <= 1:
        tried = 0
        for password in candidates:
            tried += 1
            found = worker((str(path), password))
            if found is not None:
                return AttackResult(
                    success=True,
                    password=found,
                    candidates_tried=tried,
                    message="password found",
                )
        return AttackResult(
            success=False,
            password=None,
            candidates_tried=tried,
            message="password not found in candidate set",
        )

    # Parallel: submit in batches; stop early when found.
    tried = 0
    with ProcessPoolExecutor(max_workers=options.workers) as pool:
        futures = {pool.submit(worker, (str(path), password)): password for password in candidates}
        for future in as_completed(futures):
            tried += 1
            try:
                result = future.result()
            except Exception:
                result = None
            if result is not None:
                # Cancel remaining work best-effort
                for pending in futures:
                    pending.cancel()
                return AttackResult(
                    success=True,
                    password=result,
                    candidates_tried=tried,
                    message="password found",
                )
    return AttackResult(
        success=False,
        password=None,
        candidates_tried=tried,
        message="password not found in candidate set",
    )
