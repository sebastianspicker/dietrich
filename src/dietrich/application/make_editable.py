"""Complete make-editable use case with one verified publication transaction."""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path

from dietrich.application.assess import assess_document, enforce_operation_blockers
from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.domain.models import DocumentFormat, RemovalCounts, UnlockOptions, UnlockResult
from dietrich.errors import (
    EncryptedDocumentError,
    InvalidDocumentError,
    MissingDependencyError,
    UnsupportedFormatError,
)
from dietrich.operation import checkpoint
from dietrich.safety.artifact_transaction import ArtifactTransaction
from dietrich.safety.bounded_io import read_file_prefix

OOXML_FORMATS = frozenset(
    {
        DocumentFormat.EXCEL_OOXML,
        DocumentFormat.WORD_OOXML,
        DocumentFormat.POWERPOINT_OOXML,
    }
)
CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def make_editable_copy(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions | None = None,
) -> UnlockResult:
    """Transform one document and publish exactly one validated working copy."""
    return _make_editable_copy(input_path, output_path, options, required_format=None)


def make_editable_workbook(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions,
) -> UnlockResult:
    """Create an editable copy only when the snapshotted input is Excel OOXML."""
    return _make_editable_copy(
        input_path,
        output_path,
        options,
        required_format=DocumentFormat.EXCEL_OOXML,
    )


def _make_editable_copy(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions | None,
    *,
    required_format: DocumentFormat | None,
) -> UnlockResult:
    source = Path(input_path)
    target = Path(output_path)
    options = options or UnlockOptions()
    with ArtifactTransaction(target, overwrite=options.overwrite) as transaction:
        snapshot = transaction.snapshot_source(source)
        inspection = assess_document(snapshot)
        enforce_operation_blockers(inspection)
        if required_format is not None and inspection.document_format != required_format:
            raise InvalidDocumentError(
                f"{source} is not an {required_format.value} document "
                f"(found {inspection.document_format.value})."
            )
        checkpoint("writing")
        artifact = _write_candidate(snapshot, inspection, options, transaction)
        artifact = replace(artifact, source_path=source)
        checkpoint("signing")
        artifact = _maybe_sign(artifact, options, transaction)
        transaction.commit(artifact, validate_semantics=_validate_artifact_semantics)

    return UnlockResult(
        input_path=source,
        output_path=target,
        removed=artifact.removed,
        document_format=artifact.result_document_format or artifact.document_format,
        vba_project_present=artifact.vba_project_present,
        password_used=artifact.password_used,
        warnings=artifact.warnings,
    )


def _validate_artifact_semantics(artifact: CandidateArtifact) -> None:
    """Require format-owned identity validation immediately before publication."""
    if artifact.kind == ArtifactKind.OOXML:
        from dietrich.ooxml.package import validate_ooxml_identity

        validate_ooxml_identity(artifact.path, artifact.document_format)


def _write_candidate(source, inspection, options, transaction) -> CandidateArtifact:
    if _needs_office_decryption(source, inspection.document_format):
        if options.soft_only:
            raise EncryptedDocumentError(
                "Document is open-password encrypted; soft-only mode cannot decrypt it."
            )
        return _write_decrypted_office_candidate(source, inspection, options, transaction)
    if inspection.document_format == DocumentFormat.PDF:
        return _write_pdf_candidate(source, inspection, options, transaction)
    if inspection.document_format in OOXML_FORMATS:
        from dietrich.ooxml.package import write_ooxml_candidate

        return write_ooxml_candidate(source, transaction.candidate_path(source.suffix), options)
    if inspection.document_format == DocumentFormat.LEGACY_CFBF:
        from dietrich.legacy.binary_soft import write_legacy_candidate

        return write_legacy_candidate(source, transaction.candidate_path(source.suffix), options)
    raise UnsupportedFormatError(
        f"Unsupported format for {source.name} ({inspection.document_format.value}). "
        "Supported: xlsx/xlsm/docx/docm/pptx/pptm/pdf, binary xls/doc/ppt soft unlock, "
        "and open-password Office encryption."
    )


def _write_pdf_candidate(source, inspection, options, transaction) -> CandidateArtifact:
    from dietrich.pdf.permissions import write_pdf_candidate

    if inspection.user_password_required and not options.soft_only:
        from dietrich.application.passwords import recover_pdf_password

        options = replace(
            options, password=recover_pdf_password(source, options, inspection=inspection)
        )
    return write_pdf_candidate(source, transaction.candidate_path(".pdf"), options)


def _write_decrypted_office_candidate(
    source: Path, inspection, options: UnlockOptions, transaction: ArtifactTransaction
) -> CandidateArtifact:
    from dietrich.application.passwords import recover_office_password
    from dietrich.ooxml import encryption

    password = recover_office_password(source, options, inspection=inspection)
    decrypted = transaction.candidate_path(source.suffix or ".bin")
    checkpoint("decrypting")
    encryption.decrypt_to(source, password, decrypted)
    checkpoint("writing")
    header = read_file_prefix(decrypted, 8)
    warnings = ["Decrypted open-password protected Office file."]

    if header[:2] == b"PK":
        from dietrich.ooxml.package import write_ooxml_candidate

        soft_options = _soft_options(options)
        artifact = write_ooxml_candidate(
            decrypted,
            transaction.candidate_path(source.suffix or ".zip"),
            soft_options,
        )
        warnings.extend(artifact.warnings)
        return replace(
            artifact,
            source_path=source,
            result_document_format=DocumentFormat.ENCRYPTED_OOXML,
            password_used=password,
            warnings=tuple(warnings),
        )
    if header.startswith(CFBF_MAGIC):
        candidate = transaction.candidate_path(source.suffix or ".bin")
        shutil.copyfile(decrypted, candidate)
        warnings.append(
            "Decrypted payload is binary Office; wrote it without an additional soft rewrite."
        )
        return CandidateArtifact(
            path=candidate,
            source_path=source,
            kind=ArtifactKind.LEGACY_OFFICE,
            document_format=DocumentFormat.LEGACY_CFBF,
            result_document_format=DocumentFormat.ENCRYPTED_OOXML,
            removed=RemovalCounts(),
            password_used=password,
            warnings=tuple(warnings),
        )
    raise UnsupportedFormatError(
        "decrypted Office payload is not a valid OOXML ZIP or OLE/CFB file."
    )


def _soft_options(options: UnlockOptions) -> UnlockOptions:
    return UnlockOptions(
        remove_worksheet_protection=options.remove_worksheet_protection,
        remove_workbook_protection=options.remove_workbook_protection,
        remove_document_protection=options.remove_document_protection,
        remove_modify_verifier=options.remove_modify_verifier,
        remove_mark_as_final=options.remove_mark_as_final,
        strip_signatures=options.strip_signatures,
        unlock_vba=options.unlock_vba,
        overwrite=True,
    )


def _maybe_sign(
    artifact: CandidateArtifact,
    options: UnlockOptions,
    transaction: ArtifactTransaction,
) -> CandidateArtifact:
    if not options.resign_cert or not options.resign_key:
        return artifact
    if artifact.kind != ArtifactKind.OOXML:
        raise UnsupportedFormatError(
            "--resign-cert/--resign-key only applies to an OOXML working copy."
        )
    from dietrich.ooxml.signatures.resign import write_signed_candidate

    signed_path = transaction.candidate_path(".zip")
    write_signed_candidate(
        artifact.path,
        signed_path,
        cert_pem=Path(options.resign_cert),
        key_pem=Path(options.resign_key),
    )
    return replace(
        artifact,
        path=signed_path,
        warnings=artifact.warnings
        + ("Re-signed package with user-supplied certificate (honest re-sign).",),
    )


def _needs_office_decryption(source: Path, document_format: DocumentFormat) -> bool:
    if document_format in OOXML_FORMATS or document_format == DocumentFormat.PDF:
        return False
    if document_format == DocumentFormat.ENCRYPTED_OOXML:
        return True
    try:
        from dietrich.ooxml.encryption import is_encrypted_office_file

        return is_encrypted_office_file(source)
    except (AttributeError, MissingDependencyError, OSError, TypeError, ValueError):
        return False


__all__ = ["make_editable_copy", "make_editable_workbook"]
