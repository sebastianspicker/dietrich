"""PDF open-password try/decrypt and hash export entrypoints (pikepdf).

Permission strip lives in :mod:`dietrich.pdf.permissions`; this module focuses
on user-password crypto and hash export routing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError


def _require_pikepdf():
    """Import pikepdf or raise MissingDependencyError."""
    try:
        import pikepdf
    except ImportError as exc:
        raise MissingDependencyError(
            "PDF crypto/permissions require the pdf extra: pip install 'dietrich[pdf]' (pikepdf)."
        ) from exc
    return pikepdf


def try_password(path: Path, password: str) -> bool:
    """True if pikepdf can open the PDF with the password."""
    pikepdf = _require_pikepdf()
    try:
        with pikepdf.open(path, password=password or ""):
            return True
    except pikepdf.PasswordError:
        return False
    except Exception:
        return False


def decrypt_to(
    path: Path,
    password: str,
    output_path: Path,
    *,
    strip_permissions: bool = True,
) -> None:
    """Save PDF without encryption using the given user password."""
    del strip_permissions
    pikepdf = _require_pikepdf()
    try:
        with pikepdf.open(path, password=password or "", allow_overwriting_input=False) as pdf:
            pdf.save(output_path, encryption=False)
    except pikepdf.PasswordError as exc:
        raise EncryptedDocumentError("incorrect password for encrypted PDF") from exc


def export_hash_line(path: Path, fmt: str = "hashcat") -> str:
    """Export a crackable PDF hash (native first, pdf2john fallback)."""
    path = Path(path)
    try:
        return _native_hash_line(path, fmt)
    except Exception as exc:
        native_error = exc
    fallback = _pdf2john_hash_line(path, fmt)
    if fallback is not None:
        return fallback
    raise EncryptedDocumentError(f"could not export PDF hash for {path.name}: {native_error}")


def _native_hash_line(path: Path, fmt: str) -> str:
    """Ask the native parser for a hash before invoking an external fallback."""
    from dietrich.crypto.pdf_hash import export_pdf_hash

    return export_pdf_hash(path, fmt=fmt)


def _pdf2john_hash_line(path: Path, fmt: str) -> str | None:
    """Run a controlled pdf2john argv and normalize its first non-empty line."""
    executable = shutil.which("pdf2john.pl") or shutil.which("pdf2john")
    if executable is None:
        return None
    try:
        process = subprocess.run(
            [executable, str(path)], check=False, capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return _normalize_pdf2john_output(process.stdout or "", fmt)


def _normalize_pdf2john_output(output: str, fmt: str) -> str | None:
    """Select pdf2john's first line and strip its filename prefix for hashcat."""
    line = next((line.strip() for line in output.splitlines() if line.strip()), None)
    if line is None:
        return None
    if fmt == "hashcat" and ":" in line and not line.startswith("$"):
        return line.split(":", 1)[-1]
    return line
