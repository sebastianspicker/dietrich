"""Strip PDF owner/permission restrictions (and encryption when openable)."""

from __future__ import annotations

from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError, OutputExistsError
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.types import DocumentFormat, RemovalCounts, UnlockOptions, UnlockResult


def unlock_pdf(input_path: Path, output_path: Path, options: UnlockOptions) -> UnlockResult:
    """Write a PDF copy with encryption/restrictions stripped when openable."""
    pikepdf = _load_pikepdf()
    source = Path(input_path)
    target = Path(output_path)
    _require_output_path(target, options)

    password = options.password or ""
    with temporary_output_path(target) as temp_path:
        stripped = _save_unrestricted_pdf(pikepdf, source, temp_path, password, options)
        publish_output(temp_path, target, overwrite=options.overwrite)

    warnings = ("PDF encryption/restrictions removed from working copy.",) if stripped else ()
    return UnlockResult(
        input_path=source,
        output_path=target,
        removed=RemovalCounts(pdf_permission_strips=stripped),
        document_format=DocumentFormat.PDF,
        password_used=password or None,
        warnings=warnings,
    )


def _load_pikepdf():
    """Import the optional PDF backend with the established user-facing error."""
    try:
        import pikepdf
    except ImportError as exc:
        raise MissingDependencyError(
            "PDF unlock requires: pip install 'dietrich[pdf]' (pikepdf)."
        ) from exc
    return pikepdf


def _require_output_path(target: Path, options: UnlockOptions) -> None:
    """Fail before work when the requested output already exists."""
    if target.exists() and not options.overwrite:
        raise OutputExistsError(f"{target} already exists.")


def _save_unrestricted_pdf(
    pikepdf, source: Path, temp_path: Path, password: str, options: UnlockOptions
) -> int:
    """Open a PDF with the supplied password and save an unencrypted working copy."""
    try:
        with pikepdf.open(source, password=password) as pdf:
            was_encrypted = bool(pdf.is_encrypted)
            pdf.save(temp_path, encryption=False)
    except pikepdf.PasswordError as exc:
        raise EncryptedDocumentError(
            "PDF requires a user password. Pass --password / --wordlist / --mask."
        ) from exc
    return int(was_encrypted or options.strip_pdf_permissions)
