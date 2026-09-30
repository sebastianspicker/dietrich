"""Password resolution for encrypted Office and PDF transformations."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dietrich.crypto.attack import AttackOptions, run_file_attack
from dietrich.domain.models import UnlockOptions
from dietrich.errors import EncryptedDocumentError, PasswordNotFoundError
from dietrich.operation import checkpoint

if TYPE_CHECKING:
    from dietrich.domain.models import DocumentInspection


def recover_office_password(
    source: Path,
    options: UnlockOptions,
    *,
    inspection: DocumentInspection | None = None,
) -> str:
    """Resolve an Office open password from explicit or configured local sources."""
    from dietrich.ooxml import encryption

    checkpoint("recovering password")
    if options.password is not None:
        if encryption.try_password(source, options.password):
            checkpoint()
            return options.password
        raise EncryptedDocumentError("provided password is incorrect.")
    if options.use_hashcat:
        return _recover_via_hashcat(source, options, inspection=inspection)
    if not any([options.wordlist, options.mask, options.charset]):
        raise EncryptedDocumentError(
            "Encrypted Office file requires --password, --wordlist, --mask, --brute, or --hashcat."
        )
    return _run_local_attack(source, options, kind="ooxml")


def recover_pdf_password(
    source: Path,
    options: UnlockOptions,
    *,
    inspection: DocumentInspection | None = None,
) -> str:
    """Resolve a PDF user password from explicit or configured local sources."""
    from dietrich.pdf import recovery

    checkpoint("recovering password")
    if options.password is not None:
        if recovery.try_password(source, options.password):
            checkpoint()
            return options.password
        raise EncryptedDocumentError("provided PDF password is incorrect.")
    if options.use_hashcat:
        return _recover_via_hashcat(source, options, inspection=inspection)
    if not any([options.wordlist, options.mask, options.charset]):
        raise EncryptedDocumentError(
            "Encrypted PDF requires --password, --wordlist, --mask, --brute, or --hashcat."
        )
    return _run_local_attack(source, options, kind="pdf")


def _run_local_attack(source: Path, options: UnlockOptions, *, kind: str) -> str:
    attack = AttackOptions(
        wordlist=options.wordlist,
        mask=options.mask,
        charset=options.charset,
        max_length=options.max_length,
        max_candidates=options.max_candidates,
        workers=options.workers,
    )
    worker = _try_ooxml_password if kind == "ooxml" else _try_pdf_password
    result = run_file_attack(source, attack, worker=worker)
    if not result.success or result.password is None:
        raise PasswordNotFoundError(result.message)
    return result.password


def _try_ooxml_password(args: tuple[str, str]) -> str | None:
    """Process-safe OOXML password verifier selected by the application layer."""
    path, password = args
    from dietrich.ooxml.encryption import try_password

    return _verified_password(Path(path), password, try_password)


def _try_pdf_password(args: tuple[str, str]) -> str | None:
    """Process-safe PDF password verifier selected by the application layer."""
    path, password = args
    from dietrich.pdf.recovery import try_password

    return _verified_password(Path(path), password, try_password)


def _verified_password(path: Path, password: str, verifier) -> str | None:
    try:
        return password if verifier(path, password) else None
    except (EncryptedDocumentError, OSError, RuntimeError, TypeError, ValueError):
        return None


def _recover_via_hashcat(
    source: Path,
    options: UnlockOptions,
    *,
    inspection: DocumentInspection | None,
) -> str:
    from dietrich.crypto.hashcat_runner import run_hashcat, suggest_mode_from_hash

    if not (options.wordlist or options.mask or options.hashcat_args):
        raise EncryptedDocumentError(
            "--hashcat requires --wordlist, --mask, or --hashcat-arg (attack material)."
        )
    from dietrich.application.hash_export import export_assessed_hash, export_document_hash

    hash_line = (
        export_document_hash(source, "hashcat")
        if inspection is None
        else export_assessed_hash(source, inspection, "hashcat")
    )
    mode = suggest_mode_from_hash(hash_line)
    result = run_hashcat(
        hash_line,
        mode=mode,
        wordlist=options.wordlist,
        mask=options.mask,
        extra_args=list(options.hashcat_args),
        timeout=options.hashcat_timeout,
    )
    if not result.success or not result.password:
        raise PasswordNotFoundError(result.message)
    return result.password


__all__ = ["recover_office_password", "recover_pdf_password"]
