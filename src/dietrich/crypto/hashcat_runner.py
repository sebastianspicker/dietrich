"""Thin wrapper around external hashcat for GPU password recovery.

Exports are produced elsewhere; this module builds argv (``-a 0`` wordlist or
``-a 3`` mask), runs hashcat, and reads potfile/outfile for an exact hash match.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError, PasswordNotFoundError
from dietrich.process import ProcessResult, run_hashcat_argv_sync


@dataclass(frozen=True)
class HashcatRunResult:
    """Outcome of an external hashcat invocation (password or failure)."""

    success: bool
    password: str | None
    mode: int | None
    command: tuple[str, ...]
    stdout_tail: str
    message: str


@dataclass(frozen=True)
class _HashcatFiles:
    """Temporary and persistent file locations used by one hashcat invocation."""

    pot: Path
    output: Path
    hash_input: Path


@dataclass(frozen=True)
class _HashcatOptions:
    """Inputs that define one hashcat attack while its files stay private."""

    mode: int
    wordlist: Path | None
    mask: str | None
    extra_args: tuple[str, ...]
    workload: str
    timeout: int | None


def find_hashcat() -> str:
    """Return path to hashcat on PATH or raise MissingDependencyError."""
    for name in ("hashcat", "hashcat.bin"):
        path = shutil.which(name)
        if path:
            return path
    raise MissingDependencyError(
        "hashcat not found on PATH. Install hashcat "
        "(https://hashcat.net/hashcat/) and ensure `hashcat` is available."
    )


def normalize_hash_body(hash_line: str) -> str:
    """Strip optional filename: prefix; return bare $office$… / $pdf$… body."""
    body = hash_line.strip()
    if ":$" in body and not body.startswith("$"):
        body = body.split(":", 1)[1]
    return body.strip()


def run_hashcat_for_office(
    hash_line: str,
    *,
    mode: int,
    wordlist: Path | None = None,
    mask: str | None = None,
    extra_args: list[str] | None = None,
    workload: str = "2",
    potfile: Path | None = None,
    timeout: int | None = None,
) -> HashcatRunResult:
    """Run hashcat against a single Office/PDF hash line; return cracked password if any.

    Attack modes:
    - wordlist → ``-a 0`` + wordlist path
    - mask → ``-a 3`` + mask (hashcat mask syntax, e.g. ``?d?d?d?d``)
    - extra_args may supply additional hashcat options; if neither wordlist nor mask
      is set, extra_args alone must supply a complete attack (caller validates).
    """
    options = _HashcatOptions(
        mode=mode,
        wordlist=wordlist,
        mask=mask,
        extra_args=tuple(extra_args or ()),
        workload=workload,
        timeout=timeout,
    )
    hashcat = find_hashcat()

    with tempfile.TemporaryDirectory(prefix="dietrich-hashcat-") as tmp:
        workspace = Path(tmp)
        body = normalize_hash_body(hash_line)
        files = _prepare_hashcat_files(workspace, body, potfile)
        command = _hashcat_command(hashcat, options, files)
        process = _run_hashcat(command, options.timeout)
        return _hashcat_result(process, command, files, body, options.mode)


def _prepare_hashcat_files(
    workspace: Path,
    body: str,
    potfile: Path | None,
) -> _HashcatFiles:
    """Create the one-hash input and derive hashcat's adjacent working files."""
    return _HashcatFiles(
        pot=potfile or workspace / "potfile",
        output=workspace / "cracked.txt",
        hash_input=_write_hash_file(workspace, body),
    )


def _write_hash_file(directory: Path, body: str) -> Path:
    """Write one normalized hash line to hashcat's temporary input file."""
    path = directory / "hash.txt"
    path.write_text(body + "\n", encoding="utf-8")
    return path


def _hashcat_command(hashcat: str, options: _HashcatOptions, files: _HashcatFiles) -> list[str]:
    """Build a shell-free hashcat argv for a dictionary or mask attack."""
    if options.wordlist is not None and options.mask:
        raise EncryptedDocumentError("pass either --wordlist or --mask with --hashcat, not both")
    command = _hashcat_base_command(hashcat, options, files)
    if options.mask:
        command.append(options.mask)
    elif options.wordlist is not None:
        command.append(_wordlist_path(options.wordlist))
    command.extend(options.extra_args)
    return command


def _hashcat_base_command(
    hashcat: str,
    options: _HashcatOptions,
    files: _HashcatFiles,
) -> list[str]:
    """Create common argv fields while varying only hashcat's attack-mode value."""
    return [
        hashcat,
        "-m",
        str(options.mode),
        "-a",
        "3" if options.mask is not None else "0",
        "-w",
        options.workload,
        "--potfile-path",
        str(files.pot),
        "-o",
        str(files.output),
        "--outfile-format",
        "2",
        str(files.hash_input),
    ]


def _wordlist_path(wordlist: Path) -> str:
    """Validate and stringify a user-provided dictionary file."""
    path = Path(wordlist)
    if not path.is_file():
        raise EncryptedDocumentError(f"wordlist not found: {path}")
    return str(path)


def _run_hashcat(command: list[str], timeout: int | None) -> ProcessResult:
    """Run controlled hashcat argv and translate launch failures."""
    try:
        return run_hashcat_argv_sync(command, timeout=timeout)
    except TimeoutError as exc:
        raise PasswordNotFoundError(
            f"hashcat timed out after {timeout}s without finding a password"
        ) from exc
    except OSError as exc:
        raise MissingDependencyError(f"failed to execute hashcat: {exc}") from exc


def _hashcat_result(
    process: ProcessResult,
    command: list[str],
    files: _HashcatFiles,
    body: str,
    mode: int,
) -> HashcatRunResult:
    """Return a common result record after checking temporary outputs for a password."""
    output = ((process.stdout or "") + "\n" + (process.stderr or ""))[-2000:]
    password = _read_cracked_password(files.output, files.pot, body)
    if password is not None:
        return HashcatRunResult(
            True, password, mode, tuple(command), output, "password found via hashcat"
        )
    return HashcatRunResult(
        False,
        None,
        mode,
        tuple(command),
        output,
        f"hashcat did not crack the hash (exit {process.returncode})",
    )


def _hash_bodies_match(pot_hash: str, expected_body: str) -> bool:
    """True only when potfile hash refers to the same hash we submitted."""
    a = normalize_hash_body(pot_hash)
    b = normalize_hash_body(expected_body)
    if not a or not b:
        return False
    if a == b:
        return True
    # Some potfiles store without leading $ or with trailing artifacts
    if a.lstrip("$") == b.lstrip("$"):
        return True
    return False


def _read_cracked_password(out_file: Path, pot: Path, hash_body: str) -> str | None:
    """Parse potfile/outfile for an exact hash body match."""
    expected = normalize_hash_body(hash_body)
    return _outfile_password(out_file, expected) or _potfile_password(pot, expected)


def _outfile_password(out_file: Path, expected: str) -> str | None:
    """Read the final hashcat outfile entry, preserving password-only output."""
    if not out_file.is_file():
        return None
    text = out_file.read_text(encoding="utf-8", errors="ignore")
    lines = [line.strip() for line in text.splitlines()]
    line = next((line for line in reversed(lines) if line), None)
    if line is None or not _looks_like_hash_password(line):
        return line
    hashed, _, password = line.partition(":")
    return password if _hash_bodies_match(hashed, expected) else None


def _looks_like_hash_password(line: str) -> bool:
    """Recognize hashcat's hash:password output rather than a plain password."""
    return ":" in line and (line.startswith("$") or ":$" in line)


def _potfile_password(pot: Path, expected: str) -> str | None:
    """Return the first matching password from standard or filename-prefixed pot lines."""
    if not pot.is_file():
        return None
    for raw_line in pot.read_text(encoding="utf-8", errors="ignore").splitlines():
        password = _potfile_line_password(raw_line.strip(), expected)
        if password is not None:
            return password
    return None


def _potfile_line_password(line: str, expected: str) -> str | None:
    """Match one potfile line against the expected Office or PDF hash body."""
    if not line or ":" not in line:
        return None
    hashed, _, password = line.partition(":")
    if _hash_bodies_match(hashed, expected):
        return password
    dollar = line.find("$")
    last_colon = line.rfind(":")
    if 0 <= dollar < last_colon:
        return _password_after_prefixed_hash(line, dollar, last_colon, expected)
    return None


def _password_after_prefixed_hash(
    line: str, dollar: int, last_colon: int, expected: str
) -> str | None:
    """Read a name:$hash$:password potfile line after exact hash validation."""
    hashed = line[dollar:last_colon]
    if _hash_bodies_match(hashed, expected):
        return line[last_colon + 1 :]
    return None


def suggest_mode_from_hash(hash_line: str) -> int:
    """Guess hashcat mode from exported hash body."""
    body = normalize_hash_body(hash_line)
    if body.startswith("$office$2013"):
        return 9600
    if body.startswith("$office$2010"):
        return 9500
    if body.startswith("$office$2007"):
        return 9400
    if body.startswith("$pdf$"):
        m = re.match(r"\$pdf\$(\d+)\*(\d+)\*", body)
        if m:
            r = int(m.group(2))
            if r >= 5:
                return 10700
            if r >= 3:
                return 10500
            return 10400
        return 10500
    raise EncryptedDocumentError(f"cannot suggest hashcat mode for hash: {body[:60]}…")
