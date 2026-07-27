"""Strip PDF owner/permission restrictions (and encryption when openable)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError, OutputExistsError
from dietrich.safety.publish import publish_output
from dietrich.types import DocumentFormat, RemovalCounts, UnlockOptions, UnlockResult


def unlock_pdf(input_path: Path, output_path: Path, options: UnlockOptions) -> UnlockResult:
    """Write a PDF copy with encryption/restrictions stripped when openable."""
    try:
        import pikepdf
    except ImportError as exc:
        raise MissingDependencyError(
            "PDF unlock requires: pip install 'dietrich[pdf]' (pikepdf)."
        ) from exc

    source = Path(input_path)
    target = Path(output_path)
    if target.exists() and not options.overwrite:
        raise OutputExistsError(f"{target} already exists.")

    password = options.password or ""
    temp_path: Path | None = None
    stripped = 0
    warnings: list[str] = []

    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent if target.parent.exists() else None,
            delete=False,
        ) as tmp:
            temp_path = Path(tmp.name)

        try:
            with pikepdf.open(source, password=password) as pdf:
                was_encrypted = bool(pdf.is_encrypted)
                pdf.save(temp_path, encryption=False)
                if was_encrypted or options.strip_pdf_permissions:
                    stripped = 1
        except pikepdf.PasswordError as exc:
            raise EncryptedDocumentError(
                "PDF requires a user password. Pass --password / --wordlist / --mask."
            ) from exc

        publish_output(temp_path, target, overwrite=options.overwrite)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    if stripped:
        warnings.append("PDF encryption/restrictions removed from working copy.")

    return UnlockResult(
        input_path=source,
        output_path=target,
        removed=RemovalCounts(pdf_permission_strips=stripped),
        document_format=DocumentFormat.PDF,
        password_used=password or None,
        warnings=tuple(warnings),
    )
