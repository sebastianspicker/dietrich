"""Top-level inspect/unlock routing for all supported document formats.

Flow: classify → IRM gate → open-password hard path → soft OOXML/binary/PDF
→ optional honest re-sign. Public API used by the CLI and library callers.
"""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from dietrich.crypto.attack import AttackOptions, run_file_attack
from dietrich.crypto.detect import classify_path
from dietrich.crypto.hash_export import export_hash
from dietrich.errors import (
    EncryptedDocumentError,
    InvalidDocumentError,
    MissingDependencyError,
    PasswordNotFoundError,
    UnsupportedFormatError,
)
from dietrich.ooxml.package import inspect_ooxml_package, unlock_ooxml_package
from dietrich.safety.bounded_io import read_file_prefix
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.types import (
    DocumentFormat,
    DocumentInspection,
    UnlockOptions,
    UnlockResult,
    WorkbookInspection,
)

OOXML_SUFFIXES = frozenset({".xlsx", ".xlsm", ".docx", ".docm", ".pptx", ".pptm"})
EXCEL_SUFFIXES = frozenset({".xlsx", ".xlsm"})
PDF_SUFFIXES = frozenset({".pdf"})
LEGACY_SUFFIXES = frozenset({".xls", ".doc", ".ppt"})


def inspect_document(path: Path) -> DocumentInspection:
    """Classify path and return protection/encryption inspection metadata."""
    return classify_path(Path(path))


def inspect_workbook(path: Path) -> WorkbookInspection:
    """Excel-only inspect: only .xlsx/.xlsm suffixes."""
    from dietrich.safety.zip_archive import validate_archive_safety

    input_path = Path(path)
    if input_path.suffix.lower() not in EXCEL_SUFFIXES:
        raise UnsupportedFormatError("Excel workbook helpers support only .xlsx and .xlsm.")

    # Signed packages raise on Excel inspect (strict path).
    try:
        with zipfile.ZipFile(input_path) as archive:
            validate_archive_safety(archive, allow_signed=False)
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(
            f"{input_path} is not a valid OOXML ZIP. Corrupt files and "
            "open-password encrypted workbooks need: dietrich FILE --password …"
        ) from exc

    inspection = inspect_ooxml_package(input_path, allow_signed=False)
    return inspection.as_workbook_inspection()


def unlock_workbook(input_path: Path, output_path: Path, options: UnlockOptions) -> UnlockResult:
    """Excel-only unlock entry (suffix-gated to .xlsx/.xlsm)."""
    source = Path(input_path)
    if source.suffix.lower() not in EXCEL_SUFFIXES:
        raise UnsupportedFormatError("Excel workbook helpers support only .xlsx and .xlsm.")
    return unlock_ooxml_package(source, Path(output_path), options)


def unlock_document(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions | None = None,
) -> UnlockResult:
    """Multi-format unlock with soft + optional password recovery."""
    options = options or UnlockOptions()
    source = Path(input_path)
    target = Path(output_path)
    inspection = classify_path(source)

    # IRM / Purview / RMS - detect early; cannot local-decrypt without license.
    from dietrich.crypto.irm import detect_irm, irm_block_message

    irm = detect_irm(source)
    if irm.is_irm:
        raise EncryptedDocumentError(irm_block_message(irm))

    return _maybe_resign(_unlock_for_format(source, target, options, inspection), options)


def _unlock_for_format(
    source: Path, target: Path, options: UnlockOptions, inspection: DocumentInspection
) -> UnlockResult:
    """Route a classified document to the matching unlock implementation."""
    fmt = inspection.document_format
    if _needs_office_decryption(source, fmt):
        if options.soft_only:
            raise EncryptedDocumentError(
                "Document is open-password encrypted; soft-only mode cannot decrypt it."
            )
        return _unlock_encrypted_office(source, target, options)
    if _is_pdf(source, fmt):
        return _unlock_pdf(source, target, options, inspection)
    if _is_ooxml(source, fmt):
        return unlock_ooxml_package(source, target, options)
    if fmt == DocumentFormat.LEGACY_CFBF or source.suffix.lower() in LEGACY_SUFFIXES:
        from dietrich.legacy.binary_soft import unlock_binary_office

        return unlock_binary_office(source, target, options)
    raise UnsupportedFormatError(
        f"Unsupported format for {source.name} ({fmt.value}). "
        "Supported: xlsx/xlsm/docx/docm/pptx/pptm/pdf, binary xls/doc/ppt soft unlock, "
        "and open-password Office encryption."
    )


def _needs_office_decryption(source: Path, fmt: DocumentFormat) -> bool:
    """Return whether this input takes the open-password Office path."""
    return fmt == DocumentFormat.ENCRYPTED_OOXML or _is_msoffcrypto_encrypted(source)


def _is_pdf(source: Path, fmt: DocumentFormat) -> bool:
    """Recognize classified and suffix-fallback PDF inputs."""
    return fmt == DocumentFormat.PDF or source.suffix.lower() in PDF_SUFFIXES


def _is_ooxml(source: Path, fmt: DocumentFormat) -> bool:
    """Recognize classified and suffix-fallback OOXML inputs."""
    return fmt in {
        DocumentFormat.EXCEL_OOXML,
        DocumentFormat.WORD_OOXML,
        DocumentFormat.POWERPOINT_OOXML,
    } or source.suffix.lower() in OOXML_SUFFIXES


def _maybe_resign(result: UnlockResult, options: UnlockOptions) -> UnlockResult:
    """If resign cert/key set, honestly re-sign OOXML ZIP output (error otherwise)."""
    cert = getattr(options, "resign_cert", None)
    key = getattr(options, "resign_key", None)
    if not cert or not key:
        return result

    out = Path(result.output_path)
    # OOXML packages are ZIP (PK); binary Office after decrypt may not be.
    if not out.is_file() or read_file_prefix(out, 2) != b"PK":
        raise UnsupportedFormatError(
            f"cannot --resign-cert/--resign-key on non-OOXML output {out.name}; "
            "re-sign only applies to ZIP OOXML packages after unlock."
        )

    from dietrich.signatures.resign import resign_ooxml_package

    resign_ooxml_package(
        out,
        out,
        cert_pem=Path(cert),
        key_pem=Path(key),
        overwrite=True,
    )
    return UnlockResult(
        input_path=result.input_path,
        output_path=result.output_path,
        removed=result.removed,
        document_format=result.document_format,
        vba_project_present=result.vba_project_present,
        password_used=result.password_used,
        warnings=result.warnings
        + ("Re-signed package with user-supplied certificate (honest re-sign).",),
    )


def _is_msoffcrypto_encrypted(path: Path) -> bool:
    """Best-effort encrypted-Office probe; False if msoffcrypto unavailable."""
    try:
        from dietrich.crypto.ooxml_crypto import is_encrypted_office_file

        return is_encrypted_office_file(path)
    except (AttributeError, MissingDependencyError, OSError, TypeError, ValueError):
        return False


def _unlock_pdf(
    source: Path,
    target: Path,
    options: UnlockOptions,
    inspection: DocumentInspection,
) -> UnlockResult:
    """PDF path: optional user-password recover then permission strip."""
    from dietrich.pdf.permissions import unlock_pdf

    if inspection.user_password_required and not options.soft_only:
        password = _recover_password_pdf(source, options)
        options = UnlockOptions(
            **{**options.__dict__, "password": password},
        )
    return unlock_pdf(source, target, options)


def _unlock_encrypted_office(source: Path, target: Path, options: UnlockOptions) -> UnlockResult:
    """Decrypt open-password Office, then soft-unlock when payload is OOXML ZIP."""
    import shutil

    from dietrich.crypto import ooxml_crypto
    from dietrich.errors import OutputExistsError

    password = _recover_password_ooxml(source, options)

    with tempfile.TemporaryDirectory(prefix="dietrich-") as tmp:
        decrypted = Path(tmp) / f"decrypted{source.suffix or '.bin'}"
        ooxml_crypto.decrypt_to(source, password, decrypted)

        soft_options = UnlockOptions(
            remove_worksheet_protection=options.remove_worksheet_protection,
            remove_workbook_protection=options.remove_workbook_protection,
            remove_document_protection=options.remove_document_protection,
            remove_modify_verifier=options.remove_modify_verifier,
            remove_mark_as_final=options.remove_mark_as_final,
            strip_signatures=options.strip_signatures,
            unlock_vba=options.unlock_vba,
            overwrite=True,
        )
        intermediate = Path(tmp) / f"out{source.suffix or '.bin'}"
        warnings: list[str] = ["Decrypted open-password protected Office file."]
        vba_present = False
        removed = None

        # Soft-unlock only when decrypt yields OOXML ZIP.
        if read_file_prefix(decrypted, 2) == b"PK":
            result = unlock_ooxml_package(decrypted, intermediate, soft_options)
            removed = result.removed
            vba_present = result.vba_project_present
            warnings.extend(result.warnings)
        else:
            shutil.copy2(decrypted, intermediate)
            from dietrich.types import RemovalCounts

            removed = RemovalCounts()
            warnings.append(
                "Decrypted payload is not OOXML ZIP; wrote binary as-is (no soft XML strip)."
            )

        if target.exists() and not options.overwrite:
            raise OutputExistsError(f"{target} already exists.")

        with temporary_output_path(target) as published_path:
            shutil.copy2(intermediate, published_path)
            _verify_decrypted_output(published_path)
            publish_output(published_path, target, overwrite=options.overwrite)

        return UnlockResult(
            input_path=source,
            output_path=target,
            removed=removed,
            document_format=DocumentFormat.ENCRYPTED_OOXML,
            vba_project_present=vba_present,
            password_used=password,
            warnings=tuple(warnings),
        )


def _verify_decrypted_output(path: Path) -> None:
    """Validate a decrypted OOXML ZIP or legacy Office compound file before publish."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            failed_member = archive.testzip()
        if failed_member is not None:
            raise InvalidDocumentError(
                f"decrypted package failed ZIP verification at {failed_member}"
            )
        return

    from dietrich.legacy.cfb_io import CFBF_MAGIC, read_streams

    if read_file_prefix(path, len(CFBF_MAGIC)) != CFBF_MAGIC:
        raise InvalidDocumentError(
            "decrypted Office payload is not a valid OOXML ZIP or OLE/CFB file."
        )
    try:
        read_streams(path)
    except Exception as exc:
        raise InvalidDocumentError(f"decrypted OLE/CFB payload failed validation: {exc}") from exc


def _recover_password_ooxml(source: Path, options: UnlockOptions) -> str:
    """Resolve Office open password via flag, hashcat, or local attack."""
    from dietrich.crypto import ooxml_crypto

    if options.password is not None:
        if ooxml_crypto.try_password(source, options.password):
            return options.password
        raise EncryptedDocumentError("provided password is incorrect.")

    if options.use_hashcat:
        return _recover_via_hashcat(source, options, kind="office")

    if not any([options.wordlist, options.mask, options.charset]):
        raise EncryptedDocumentError(
            "Encrypted Office file requires --password, --wordlist, --mask, --brute, or --hashcat."
        )

    attack = AttackOptions(
        passwords=(),
        wordlist=options.wordlist,
        mask=options.mask,
        charset=options.charset,
        max_length=options.max_length,
        max_candidates=options.max_candidates,
        workers=options.workers,
    )
    result = run_file_attack(source, attack, kind="ooxml")
    if not result.success or result.password is None:
        raise PasswordNotFoundError(result.message)
    return result.password


def _recover_via_hashcat(source: Path, options: UnlockOptions, *, kind: str) -> str:
    """Export hash, run external hashcat, return cracked password or raise."""
    from dietrich.crypto.hashcat_runner import (
        run_hashcat_for_office,
        suggest_mode_from_hash,
    )

    has_attack = bool(options.wordlist or options.mask or options.hashcat_args)
    if not has_attack:
        raise EncryptedDocumentError(
            "--hashcat requires --wordlist, --mask, or --hashcat-arg (attack material)."
        )

    if kind == "office":
        fmt = DocumentFormat.ENCRYPTED_OOXML
    else:
        fmt = DocumentFormat.PDF
    hash_line = export_hash(source, fmt, "hashcat")
    mode = suggest_mode_from_hash(hash_line)
    hc = run_hashcat_for_office(
        hash_line,
        mode=mode,
        wordlist=options.wordlist,
        mask=options.mask,
        extra_args=list(options.hashcat_args),
        timeout=options.hashcat_timeout,
    )
    if not hc.success or not hc.password:
        raise PasswordNotFoundError(hc.message)
    return hc.password


def _recover_password_pdf(source: Path, options: UnlockOptions) -> str:
    """Resolve PDF user password via flag, hashcat, or local attack."""
    from dietrich.crypto import pdf_crypto

    if options.password is not None:
        if pdf_crypto.try_password(source, options.password):
            return options.password
        raise EncryptedDocumentError("provided PDF password is incorrect.")

    if options.use_hashcat:
        return _recover_via_hashcat(source, options, kind="pdf")

    if not any([options.wordlist, options.mask, options.charset]):
        raise EncryptedDocumentError(
            "Encrypted PDF requires --password, --wordlist, --mask, --brute, or --hashcat."
        )
    attack = AttackOptions(
        wordlist=options.wordlist,
        mask=options.mask,
        charset=options.charset,
        max_length=options.max_length,
        max_candidates=options.max_candidates,
        workers=options.workers,
    )
    result = run_file_attack(source, attack, kind="pdf")
    if not result.success or result.password is None:
        raise PasswordNotFoundError(result.message)
    return result.password


def export_document_hash(path: Path, fmt: str = "hashcat") -> str:
    """Export a crackable hash line for the document (Office or PDF)."""
    inspection = classify_path(Path(path))
    return export_hash(Path(path), inspection.document_format, fmt)
