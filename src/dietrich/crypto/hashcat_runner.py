"""Thin wrapper around external hashcat for GPU password recovery.

Exports are produced elsewhere; this module builds argv (``-a 0`` wordlist or
``-a 3`` mask), runs hashcat, and reads potfile/outfile for an exact hash match.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError, PasswordNotFoundError


@dataclass(frozen=True)
class HashcatRunResult:
    """Outcome of an external hashcat invocation (password or failure)."""

    success: bool
    password: str | None
    mode: int | None
    command: tuple[str, ...]
    stdout_tail: str
    message: str


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
    hashcat = find_hashcat()
    extra_args = list(extra_args or [])

    with tempfile.TemporaryDirectory(prefix="dietrich-hashcat-") as tmp:
        tmp_path = Path(tmp)
        hash_file = tmp_path / "hash.txt"
        body = normalize_hash_body(hash_line)
        hash_file.write_text(body + "\n", encoding="utf-8")

        out_file = tmp_path / "cracked.txt"
        pot = potfile or (tmp_path / "potfile")

        if wordlist is not None and mask:
            raise EncryptedDocumentError(
                "pass either --wordlist or --mask with --hashcat, not both"
            )

        if mask:
            # Mask attack (-a 3)
            cmd = [
                hashcat,
                "-m",
                str(mode),
                "-a",
                "3",
                "-w",
                workload,
                "--potfile-path",
                str(pot),
                "-o",
                str(out_file),
                "--outfile-format",
                "2",
                str(hash_file),
                mask,
            ]
        else:
            # Dictionary attack (-a 0); wordlist optional if extra_args supplies attack
            cmd = [
                hashcat,
                "-m",
                str(mode),
                "-a",
                "0",
                "-w",
                workload,
                "--potfile-path",
                str(pot),
                "-o",
                str(out_file),
                "--outfile-format",
                "2",
                str(hash_file),
            ]
            if wordlist is not None:
                wl = Path(wordlist)
                if not wl.is_file():
                    raise EncryptedDocumentError(f"wordlist not found: {wl}")
                cmd.append(str(wl))

        cmd.extend(extra_args)

        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise PasswordNotFoundError(
                f"hashcat timed out after {timeout}s without finding a password"
            ) from exc
        except OSError as exc:
            raise MissingDependencyError(f"failed to execute hashcat: {exc}") from exc

        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        password = _read_cracked_password(out_file, pot, body)
        if password is not None:
            return HashcatRunResult(
                success=True,
                password=password,
                mode=mode,
                command=tuple(cmd),
                stdout_tail=combined[-2000:],
                message="password found via hashcat",
            )

        return HashcatRunResult(
            success=False,
            password=None,
            mode=mode,
            command=tuple(cmd),
            stdout_tail=combined[-2000:],
            message=f"hashcat did not crack the hash (exit {proc.returncode})",
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
    if out_file.is_file():
        text = out_file.read_text(encoding="utf-8", errors="ignore")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if lines:
            line = lines[-1]
            # outfile-format 2 = password only
            # format 3 / pot-like: hash:password - only accept if hash matches
            if ":" in line and (line.startswith("$") or ":$" in line):
                h, _, pw = line.partition(":")
                if _hash_bodies_match(h, expected):
                    return pw
                # If left side is not a hash (plain password containing colon), take whole
                if not line.startswith("$") and ":$" not in line:
                    return line
                return None
            return line
    if pot.is_file():
        for line in pot.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # potfile: hash:password (hash may contain ':' in rare formats - use rsplit once
            # from first colon after hash markers is fragile; standard is hash:pass with hash
            # containing no unescaped colon for office/pdf.)
            h, _, pw = line.partition(":")
            if _hash_bodies_match(h, expected):
                return pw
            # name:$office$...:password (hash itself has no colons)
            dollar = line.find("$")
            last_colon = line.rfind(":")
            if dollar >= 0 and last_colon > dollar:
                h2 = line[dollar:last_colon]
                pw2 = line[last_colon + 1 :]
                if _hash_bodies_match(h2, expected):
                    return pw2
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
