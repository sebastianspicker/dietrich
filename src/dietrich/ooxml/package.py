"""OOXML ZIP package inspect/unlock pipeline.

Applies format transformers per part, optional signature strip and VBA clear,
preserves ZipInfo metadata, and writes a verified unpublished candidate.
"""

from __future__ import annotations

import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.domain.models import (
    DocumentFormat,
    DocumentInspection,
    UnlockOptions,
)
from dietrich.errors import InvalidDocumentError
from dietrich.ooxml.excel import (
    VBA_PROJECT_PATHS,
    inspect_excel_parts,
    transform_excel_part,
)
from dietrich.ooxml.powerpoint import inspect_powerpoint_parts, transform_powerpoint_part
from dietrich.ooxml.props import inspect_props_parts, transform_props_part
from dietrich.ooxml.signatures.strip import strip_signature_members
from dietrich.ooxml.stats import PartStats
from dietrich.ooxml.word import inspect_word_parts, transform_word_part
from dietrich.safety.zip_archive import package_is_signed, validate_archive_safety

Transformer = Callable[[str, bytes, UnlockOptions, PartStats], bytes]


@dataclass
class ArchiveRewriteContext:
    """Mutable state shared while rewriting one OOXML ZIP archive."""

    source: zipfile.ZipFile
    transformers: list[Transformer]
    skip_names: set[str]
    rewritten_parts: dict[str, bytes]
    options: UnlockOptions
    stats: PartStats
    warnings: list[str]


MAIN_PART_FORMATS = {
    "xl/workbook.xml": DocumentFormat.EXCEL_OOXML,
    "word/document.xml": DocumentFormat.WORD_OOXML,
    "ppt/presentation.xml": DocumentFormat.POWERPOINT_OOXML,
}


def identify_ooxml_format(names: list[str]) -> DocumentFormat:
    """Identify exactly one defining OOXML main part; reject decoys and ambiguity."""
    normalized = {name.replace("\\", "/") for name in names}
    formats = {fmt for part, fmt in MAIN_PART_FORMATS.items() if part in normalized}
    if len(formats) != 1:
        return DocumentFormat.UNKNOWN
    return formats.pop()


def _transformers_for(fmt: DocumentFormat) -> list[Transformer]:
    common: list[Transformer] = [transform_props_part]
    if fmt == DocumentFormat.EXCEL_OOXML:
        return [transform_excel_part, *common]
    if fmt == DocumentFormat.WORD_OOXML:
        return [transform_word_part, *common]
    if fmt == DocumentFormat.POWERPOINT_OOXML:
        return [transform_powerpoint_part, *common]
    return common


def inspect_ooxml_package(path: Path, *, allow_signed: bool = False) -> DocumentInspection:
    """List soft protections and strategies for an OOXML ZIP."""
    input_path = Path(path)
    try:
        with zipfile.ZipFile(input_path) as archive:
            validate_archive_safety(archive, allow_signed=allow_signed)
            names = archive.namelist()
            fmt = identify_ooxml_format(names)
            signed = package_is_signed(names)
            vba = any(p in names for p in VBA_PROJECT_PATHS)

            soft, strategies = _inspect_format_parts(fmt, names, archive.read)
            soft.extend(inspect_props_parts(names, archive.read))
            if signed:
                strategies.append("signature:strip")
            if vba:
                strategies.append("vba:unlock")

            notes: list[str] = []
            if signed:
                notes.append("Package is digitally signed; default unlock rejects rewrite.")
            if vba:
                notes.append("VBA project present; password clear requires --vba.")

            return DocumentInspection(
                input_path=input_path,
                document_format=fmt,
                strategies=tuple(strategies),
                soft_protections=tuple(soft),
                encrypted=False,
                signed=signed,
                vba_project_present=vba,
                notes=tuple(notes),
            )
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(
            f"{input_path} is not a valid OOXML ZIP. Corrupt files and "
            "password-encrypted Office files need the crypto path."
        ) from exc
    except RuntimeError as exc:
        raise InvalidDocumentError(f"{input_path} could not be read: {exc}") from exc


def _inspect_format_parts(
    fmt: DocumentFormat, names: list[str], read: Callable[[str], bytes]
) -> tuple[list, list[str]]:
    """Inspect format-specific soft protections and advertise their strategies."""
    inspectors = {
        DocumentFormat.EXCEL_OOXML: (
            inspect_excel_parts,
            ["soft:sheetProtection", "soft:workbookProtection"],
        ),
        DocumentFormat.WORD_OOXML: (inspect_word_parts, ["soft:documentProtection"]),
        DocumentFormat.POWERPOINT_OOXML: (
            inspect_powerpoint_parts,
            ["soft:modifyVerifier"],
        ),
    }
    inspector = inspectors.get(fmt)
    if inspector is None:
        return [], []
    inspect_parts, strategies = inspector
    return list(inspect_parts(names, read)), list(strategies)


def write_ooxml_candidate(
    source: Path,
    candidate_path: Path,
    options: UnlockOptions,
) -> CandidateArtifact:
    """Write and verify an unpublished soft-unlocked OOXML candidate."""
    source_path = Path(source)
    candidate = Path(candidate_path)
    if candidate.resolve() == source_path.resolve():
        raise InvalidDocumentError("OOXML candidate path must differ from its source path.")

    stats = PartStats()
    warnings: list[str] = []
    fmt = DocumentFormat.UNKNOWN
    vba_present = False

    try:
        with zipfile.ZipFile(source_path) as source_archive:
            validate_archive_safety(source_archive, allow_signed=options.strip_signatures)
            names = source_archive.namelist()
            fmt = identify_ooxml_format(names)
            if fmt == DocumentFormat.UNKNOWN:
                raise InvalidDocumentError(
                    f"{source_path} is a ZIP archive but not a supported OOXML document."
                )
            vba_present = any(p in names for p in VBA_PROJECT_PATHS)
            transformers = _transformers_for(fmt)

            skip_names, rewritten_parts = _signature_rewrites(
                names, source_archive.read, options, stats, warnings
            )

            rewrite_context = ArchiveRewriteContext(
                source=source_archive,
                transformers=transformers,
                skip_names=skip_names,
                rewritten_parts=rewritten_parts,
                options=options,
                stats=stats,
                warnings=warnings,
            )
            _write_transformed_archive(candidate, rewrite_context)

        _verify_candidate_package(candidate, options, fmt)
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(
            f"{source_path} is not a valid OOXML ZIP. Corrupt files and "
            "password-encrypted Office files need the crypto path."
        ) from exc
    except RuntimeError as exc:
        raise InvalidDocumentError(f"{source_path} could not be read: {exc}") from exc

    return CandidateArtifact(
        path=candidate,
        source_path=source_path,
        kind=ArtifactKind.OOXML,
        document_format=fmt,
        removed=stats.to_removal_counts(),
        vba_project_present=vba_present,
        warnings=tuple(warnings),
    )


def _verify_candidate_package(
    candidate_path: Path, options: UnlockOptions, expected_format: DocumentFormat
) -> None:
    """Check the written OOXML candidate before returning it to its publisher."""
    with zipfile.ZipFile(candidate_path) as output_archive:
        validate_archive_safety(output_archive, allow_signed=options.strip_signatures)
        actual_format = identify_ooxml_format(output_archive.namelist())
        if actual_format != expected_format:
            raise InvalidDocumentError(
                f"written OOXML identity changed: expected {expected_format.value}, "
                f"found {actual_format.value}"
            )
        failed_member = output_archive.testzip()
    if failed_member is not None:
        raise InvalidDocumentError(f"written package failed ZIP verification at {failed_member}")


def validate_ooxml_identity(path: Path, expected_format: DocumentFormat) -> None:
    """Recheck a final candidate's defining main part against its declared format."""
    try:
        with zipfile.ZipFile(path) as archive:
            actual = identify_ooxml_format(archive.namelist())
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(f"{path} is not a valid OOXML ZIP: {exc}") from exc
    if actual != expected_format:
        raise InvalidDocumentError(
            f"OOXML candidate identity mismatch: expected {expected_format.value}, "
            f"found {actual.value}"
        )


def _signature_rewrites(
    names: list[str],
    read: Callable[[str], bytes],
    options: UnlockOptions,
    stats: PartStats,
    warnings: list[str],
) -> tuple[set[str], dict[str, bytes]]:
    """Return signature members to omit and relationship/content-type replacements."""
    if not options.strip_signatures or not package_is_signed(names):
        return set(), {}
    skip_names, rewritten_parts = strip_signature_members(names, read)
    stats.add("signatures", 1 if skip_names else 0)
    warnings.append(
        "Digital signatures were stripped. The output is an unsigned working copy; "
        "authenticity of the original signer is no longer asserted."
    )
    return skip_names, rewritten_parts


def _write_transformed_archive(
    temp_path: Path,
    context: ArchiveRewriteContext,
) -> None:
    """Rewrite each retained ZIP member while preserving member metadata."""
    with zipfile.ZipFile(temp_path, "w") as target:
        for info in context.source.infolist():
            name = info.filename.replace("\\", "/")
            if name not in context.skip_names:
                target.writestr(
                    _copy_zip_info(info),
                    _rewrite_member(context, info),
                )


def _rewrite_member(
    context: ArchiveRewriteContext,
    info: zipfile.ZipInfo,
) -> bytes:
    """Apply XML and optional VBA transforms to one source member."""
    name = info.filename.replace("\\", "/")
    data = context.rewritten_parts.get(name, context.source.read(info))
    for transformer in context.transformers:
        data = transformer(name, data, context.options, context.stats)
    if context.options.unlock_vba and name in VBA_PROJECT_PATHS:
        from dietrich.ooxml.vba import unlock_vba_project

        data, touched = unlock_vba_project(data)
        context.stats.add("vba", touched)
        if touched == 0:
            warning = f"{name}: --vba found no CMG/DPB/GC text (project stream may be compressed)."
            if warning not in context.warnings:
                context.warnings.append(warning)
    return data


def _copy_zip_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    """Clone the ZIP metadata that must survive a package rewrite."""
    copied = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
    copied.compress_type = info.compress_type
    copied.comment = info.comment
    copied.extra = info.extra
    copied.create_system = info.create_system
    copied.create_version = info.create_version
    copied.extract_version = info.extract_version
    copied.flag_bits = info.flag_bits
    copied.internal_attr = info.internal_attr
    copied.external_attr = info.external_attr
    return copied
