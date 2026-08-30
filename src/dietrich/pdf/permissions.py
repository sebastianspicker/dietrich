"""Write an unpublished PDF candidate with protections stripped."""

from __future__ import annotations

from pathlib import Path

from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.domain.models import DocumentFormat, RemovalCounts, UnlockOptions
from dietrich.errors import EncryptedDocumentError, InvalidDocumentError, MissingDependencyError


def write_pdf_candidate(
    source: Path, candidate_path: Path, options: UnlockOptions
) -> CandidateArtifact:
    """Write and validate an unpublished, unrestricted PDF candidate.

    Publication is intentionally owned by the application layer.  This writer
    only receives the source and an already-reserved candidate location.
    """
    pikepdf = _load_pikepdf()
    source = Path(source)
    candidate_path = Path(candidate_path)
    _require_distinct_candidate(source, candidate_path)

    password = options.password or ""
    stripped = _save_unrestricted_pdf(pikepdf, source, candidate_path, password, options)
    _validate_pdf_candidate(pikepdf, candidate_path)

    warnings = ("PDF encryption/restrictions removed from working copy.",) if stripped else ()
    return CandidateArtifact(
        path=candidate_path,
        source_path=source,
        kind=ArtifactKind.PDF,
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


def _require_distinct_candidate(source: Path, candidate_path: Path) -> None:
    """Never permit a candidate writer to replace its source file."""
    if source.resolve() == candidate_path.resolve():
        raise InvalidDocumentError("PDF candidate path must differ from the source path.")


def _save_unrestricted_pdf(
    pikepdf, source: Path, candidate_path: Path, password: str, options: UnlockOptions
) -> int:
    """Open a PDF with the supplied password and save an unencrypted working copy."""
    try:
        with pikepdf.open(source, password=password) as pdf:
            was_encrypted = bool(pdf.is_encrypted)
            pdf.save(candidate_path, encryption=False)
    except pikepdf.PasswordError as exc:
        raise EncryptedDocumentError(
            "PDF requires a user password. Pass --password / --wordlist / --mask."
        ) from exc
    return int(was_encrypted)


def _validate_pdf_candidate(pikepdf, candidate_path: Path) -> None:
    """Require a non-empty, parseable, unencrypted candidate before handoff."""
    if not candidate_path.is_file() or candidate_path.stat().st_size == 0:
        raise InvalidDocumentError("PDF candidate was not written.")
    try:
        with pikepdf.open(candidate_path) as candidate:
            if candidate.is_encrypted:
                raise InvalidDocumentError("PDF candidate remains encrypted.")
    except pikepdf.PasswordError as exc:
        raise InvalidDocumentError("PDF candidate requires a password.") from exc
    except pikepdf.PdfError as exc:
        raise InvalidDocumentError(f"PDF candidate failed validation: {exc}") from exc
