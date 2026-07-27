"""OOXML ZIP package inspect/unlock pipeline.

Applies format transformers per part, optional signature strip and VBA clear,
preserves ZipInfo metadata, verifies the written archive, then atomically
publishes the output.
"""

from __future__ import annotations

import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from dietrich.errors import InvalidDocumentError
from dietrich.ooxml import excel, powerpoint, props, word
from dietrich.ooxml.excel import VBA_PROJECT_PATHS
from dietrich.safety.publish import publish_output
from dietrich.safety.zip_archive import package_is_signed, validate_archive_safety
from dietrich.signatures.strip import strip_signature_members
from dietrich.types import (
    DocumentFormat,
    DocumentInspection,
    PartStats,
    UnlockOptions,
    UnlockResult,
)

Transformer = Callable[[str, bytes, UnlockOptions, PartStats], bytes]


def _format_from_names(names: list[str]) -> DocumentFormat:
    """Internal helper: _format_from_names."""
    normalized = [n.replace("\\", "/") for n in names]
    if any(n.startswith("xl/") for n in normalized):
        return DocumentFormat.EXCEL_OOXML
    if any(n.startswith("word/") for n in normalized):
        return DocumentFormat.WORD_OOXML
    if any(n.startswith("ppt/") for n in normalized):
        return DocumentFormat.POWERPOINT_OOXML
    return DocumentFormat.UNKNOWN


def _transformers_for(fmt: DocumentFormat) -> list[Transformer]:
    """Internal helper: _transformers_for."""
    common: list[Transformer] = [props.transform_props_part]
    if fmt == DocumentFormat.EXCEL_OOXML:
        return [excel.transform_excel_part, *common]
    if fmt == DocumentFormat.WORD_OOXML:
        return [word.transform_word_part, *common]
    if fmt == DocumentFormat.POWERPOINT_OOXML:
        return [powerpoint.transform_powerpoint_part, *common]
    return common


def inspect_ooxml_package(path: Path, *, allow_signed: bool = False) -> DocumentInspection:
    """List soft protections and strategies for an OOXML ZIP."""
    input_path = Path(path)
    try:
        with zipfile.ZipFile(input_path) as archive:
            validate_archive_safety(archive, allow_signed=allow_signed)
            names = archive.namelist()
            fmt = _format_from_names(names)
            signed = package_is_signed(names)
            vba = any(p in names for p in VBA_PROJECT_PATHS)

            soft: list = []
            strategies: list[str] = []
            if fmt == DocumentFormat.EXCEL_OOXML:
                soft.extend(excel.inspect_excel_parts(names, archive.read))
                strategies.append("soft:sheetProtection")
                strategies.append("soft:workbookProtection")
            elif fmt == DocumentFormat.WORD_OOXML:
                soft.extend(word.inspect_word_parts(names, archive.read))
                strategies.append("soft:documentProtection")
            elif fmt == DocumentFormat.POWERPOINT_OOXML:
                soft.extend(powerpoint.inspect_powerpoint_parts(names, archive.read))
                strategies.append("soft:modifyVerifier")
            soft.extend(props.inspect_props_parts(names, archive.read))
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


def unlock_ooxml_package(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions,
) -> UnlockResult:
    """Write a soft-unlocked copy of an OOXML package."""
    source_path = Path(input_path)
    target_path = Path(output_path)

    if target_path.exists() and not options.overwrite:
        from dietrich.errors import OutputExistsError

        raise OutputExistsError(f"{target_path} already exists.")

    stats = PartStats()
    warnings: list[str] = []
    temp_path: Path | None = None
    fmt = DocumentFormat.UNKNOWN
    vba_present = False

    try:
        with zipfile.ZipFile(source_path) as source:
            validate_archive_safety(source, allow_signed=options.strip_signatures)
            names = source.namelist()
            fmt = _format_from_names(names)
            vba_present = any(p in names for p in VBA_PROJECT_PATHS)
            transformers = _transformers_for(fmt)

            skip_names: set[str] = set()
            if options.strip_signatures and package_is_signed(names):
                skip_names, sig_extra = strip_signature_members(names, source.read)
                stats.add("signatures", 1 if skip_names else 0)
                # Apply content-type / rels rewrites from strip helper via extra map.
                rewritten_parts = sig_extra
                warnings.append(
                    "Digital signatures were stripped. The output is an unsigned working copy; "
                    "authenticity of the original signer is no longer asserted."
                )
            else:
                rewritten_parts = {}

            with tempfile.NamedTemporaryFile(
                prefix=f".{target_path.name}.",
                suffix=".tmp",
                dir=target_path.parent if target_path.parent.exists() else None,
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)

            with zipfile.ZipFile(temp_path, "w") as target:
                for info in source.infolist():
                    name = info.filename.replace("\\", "/")
                    if name in skip_names:
                        continue
                    if name in rewritten_parts:
                        original_data = rewritten_parts[name]
                    else:
                        original_data = source.read(info)

                    rewritten_data = original_data
                    for transformer in transformers:
                        rewritten_data = transformer(name, rewritten_data, options, stats)

                    if options.unlock_vba and name in VBA_PROJECT_PATHS:
                        from dietrich.ooxml.vba import unlock_vba_project

                        rewritten_data, vba_n = unlock_vba_project(rewritten_data)
                        stats.add("vba", vba_n)
                        if vba_n == 0:
                            msg = (
                                f"{name}: --vba found no CMG/DPB/GC text "
                                "(project stream may be compressed)."
                            )
                            if msg not in warnings:
                                warnings.append(msg)

                    # Preserve ZipInfo metadata (compression, timestamps, attrs).
                    out_info = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
                    out_info.compress_type = info.compress_type
                    out_info.comment = info.comment
                    out_info.extra = info.extra
                    out_info.create_system = info.create_system
                    out_info.create_version = info.create_version
                    out_info.extract_version = info.extract_version
                    out_info.flag_bits = info.flag_bits
                    out_info.internal_attr = info.internal_attr
                    out_info.external_attr = info.external_attr
                    target.writestr(out_info, rewritten_data)

        with zipfile.ZipFile(temp_path) as output_archive:
            failed_member = output_archive.testzip()
        if failed_member is not None:
            raise InvalidDocumentError(
                f"written package failed ZIP verification at {failed_member}"
            )

        publish_output(temp_path, target_path, overwrite=options.overwrite)
        temp_path = None
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(
            f"{source_path} is not a valid OOXML ZIP. Corrupt files and "
            "password-encrypted Office files need the crypto path."
        ) from exc
    except RuntimeError as exc:
        raise InvalidDocumentError(f"{source_path} could not be read: {exc}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    return UnlockResult(
        input_path=source_path,
        output_path=target_path,
        removed=stats.to_removal_counts(),
        document_format=fmt,
        vba_project_present=vba_present,
        warnings=tuple(warnings),
    )
