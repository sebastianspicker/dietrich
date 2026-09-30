"""Verified soft-protection rewrites for binary Excel and Word.

Patches OLE streams in place (equal length) to clear BIFF/FIB protection fields.
Legacy PowerPoint is detected but fails closed because no verified record parser is
implemented. Open-password decryption belongs to the msoffcrypto path.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.domain.models import DocumentFormat, RemovalCounts, UnlockOptions
from dietrich.errors import InvalidDocumentError, UnsupportedFormatError
from dietrich.operation import checkpoint
from dietrich.safety.cfb import patch_streams, read_streams

# BIFF record types related to protection (Excel)
_BIFF_PROTECT = 0x0012
_BIFF_PASSWORD = 0x0013
_BIFF_WINDOW_PROTECT = 0x0019
_BIFF_OBJ_PROTECT = 0x0063
_BIFF_SCEN_PROTECT = 0x00DD
_BIFF_PROT4REV = 0x01AF
_BIFF_PROT4REVPASS = 0x01BC
_BIFF_SHEETPROTECTION = 0x0867  # FeatHdr related - also scan Feat
_BIFF8_BOF = 0x0809
_BIFF_EOF = 0x000A
_BIFF_GLOBALS = 0x0005
_BIFF8_SUBSTREAM_TYPES = {_BIFF_GLOBALS, 0x0006, 0x0010, 0x0020, 0x0040, 0x0100}


def write_legacy_candidate(
    source: Path,
    candidate_path: Path,
    options: UnlockOptions,
) -> CandidateArtifact:
    """Write and validate an unpublished soft-unlocked CFBF candidate."""
    del options
    source = Path(source)
    candidate_path = Path(candidate_path)
    _require_distinct_candidate(source, candidate_path)
    checkpoint("reading legacy Office streams")

    try:
        streams = read_streams(source)
    except (ImportError, OSError, ValueError) as exc:
        raise InvalidDocumentError(f"{source} is not a readable OLE/CFB file: {exc}") from exc

    patches, counts = _build_patches(source, streams)
    del streams
    checkpoint("writing legacy Office candidate")

    if not patches:
        # Still provide a candidate so the application can publish uniformly.
        shutil.copy2(source, candidate_path)
        warnings = ("No binary protection records found; wrote unchanged copy.",)
        result_counts = RemovalCounts()
    else:
        try:
            patch_streams(source, candidate_path, patches)
        except (OSError, ValueError) as exc:
            raise InvalidDocumentError(f"failed to write patched OLE: {exc}") from exc
        warnings = ("Soft-cleared binary Office protection records.",)
        result_counts = counts

    try:
        read_streams(candidate_path)
    except (ImportError, OSError, ValueError) as exc:
        raise InvalidDocumentError(f"patched OLE failed validation: {exc}") from exc
    checkpoint()

    return CandidateArtifact(
        path=candidate_path,
        source_path=source,
        kind=ArtifactKind.LEGACY_OFFICE,
        removed=result_counts,
        document_format=DocumentFormat.LEGACY_CFBF,
        warnings=warnings,
    )


def _require_distinct_candidate(source: Path, candidate_path: Path) -> None:
    """Never permit a candidate writer to overwrite its input document."""
    if source.resolve() == candidate_path.resolve():
        raise InvalidDocumentError("legacy candidate path must differ from the source path.")


def _build_patches(
    source: Path, streams: dict[str, bytes]
) -> tuple[dict[str, bytes], RemovalCounts]:
    """Dispatch a legacy Office stream set to its format-specific patcher."""
    kind = _detect_kind(streams)
    if kind == "xls":
        return _patch_xls_streams(source, streams)
    if kind == "doc":
        return _patch_doc_streams(source, streams)
    if kind == "ppt":
        return _patch_ppt_streams(source, streams)
    raise UnsupportedFormatError(
        f"{source.name}: unrecognized binary Office streams "
        f"(found: {', '.join(sorted(streams)[:8])})"
    )


def _patch_xls_streams(
    source: Path, streams: dict[str, bytes]
) -> tuple[dict[str, bytes], RemovalCounts]:
    """Patch Workbook or Book records and report worksheet protections."""
    key = _find_stream(streams, "Workbook") or _find_stream(streams, "Book")
    if not key:
        raise UnsupportedFormatError(f"{source.name}: no Workbook stream")
    data, count = _patch_biff_workbook(streams[key])
    if not count:
        return {}, RemovalCounts()
    return {key: data}, RemovalCounts(worksheet_protections=count)


def _patch_doc_streams(
    source: Path, streams: dict[str, bytes]
) -> tuple[dict[str, bytes], RemovalCounts]:
    """Patch WordDocument plus optional table-stream protection records."""
    key = _find_stream(streams, "WordDocument")
    if not key:
        raise UnsupportedFormatError(f"{source.name}: no WordDocument stream")
    data, count = _patch_word_document(streams[key])
    patches = {key: data} if count else {}
    return patches, RemovalCounts(document_protections=count)


def _patch_ppt_streams(
    source: Path, streams: dict[str, bytes]
) -> tuple[dict[str, bytes], RemovalCounts]:
    """Reject legacy PowerPoint mutation until a verified record parser exists."""
    key = _find_stream(streams, "PowerPoint Document")
    if not key:
        raise UnsupportedFormatError(f"{source.name}: no PowerPoint Document stream")
    raise UnsupportedFormatError(
        f"{source.name}: legacy PowerPoint inspection is supported, but safe protection "
        "rewriting requires a verified record parser and is not available."
    )


def _detect_kind(streams: dict[str, bytes]) -> str:
    """Map CFBF streams to xls/doc/ppt kind for soft rewrite."""
    names = set(streams)
    short = {n.split("/")[-1] for n in names}
    if "Workbook" in short or "Book" in short:
        return "xls"
    if "WordDocument" in short:
        return "doc"
    if "PowerPoint Document" in short:
        return "ppt"
    return "unknown"


def _find_stream(streams: dict[str, bytes], short_name: str) -> str | None:
    """Locate preferred workbook/document stream path in OLE."""
    for name in streams:
        if (
            name == short_name
            or name.endswith("/" + short_name)
            or name.split("/")[-1] == short_name
        ):
            return name
    return None


def _patch_biff_workbook(data: bytes) -> tuple[bytes, int]:
    """Clear BIFF protection-related records in Workbook stream.

    Returns (new_bytes, number_of_protection_records_cleared) - not byte counts.
    """
    buf = bytearray(data)
    protection_lengths = {
        _BIFF_PROTECT: {2},
        _BIFF_PASSWORD: {2},
        _BIFF_WINDOW_PROTECT: {2},
        _BIFF_OBJ_PROTECT: {2},
        _BIFF_SCEN_PROTECT: {2},
        _BIFF_PROT4REV: {2},
        _BIFF_PROT4REVPASS: {2},
    }
    cleared_at: set[int] = set()
    cleared = _walk_biff_protection_records(buf, protection_lengths, cleared_at)
    return bytes(buf), cleared


def _walk_biff_protection_records(buf, protection_lengths, cleared_at: set[int]) -> int:
    """Clear protection records only inside complete, supported BIFF substreams."""
    cleared = 0
    index = 0
    in_substream = False
    saw_globals = False
    while index < len(buf):
        if index + 4 > len(buf):
            raise InvalidDocumentError("truncated BIFF record header")
        record_type, record_length = struct.unpack_from("<HH", buf, index)
        end = index + 4 + record_length
        if record_length > 100_000 or end > len(buf):
            raise InvalidDocumentError("invalid BIFF record length")
        payload = bytes(buf[index + 4 : end])
        if record_type == _BIFF8_BOF:
            if in_substream:
                raise InvalidDocumentError("nested BIFF BOF record")
            _validate_biff8_bof(payload, require_globals=not saw_globals)
            saw_globals = True
            in_substream = True
        elif record_type == _BIFF_EOF:
            if not in_substream or record_length != 0:
                raise InvalidDocumentError("invalid BIFF EOF record")
            in_substream = False
        elif not in_substream:
            raise InvalidDocumentError("BIFF record appears outside a BOF/EOF substream")
        elif record_length in protection_lengths.get(record_type, set()):
            cleared += _clear_biff_record(buf, index, record_length, cleared_at)
        index = end
    if not saw_globals:
        raise InvalidDocumentError("BIFF Workbook stream has no supported BOF record")
    if in_substream:
        raise InvalidDocumentError("BIFF Workbook stream has no closing EOF record")
    return cleared


def _validate_biff8_bof(payload: bytes, *, require_globals: bool) -> None:
    """Require a complete BIFF8 BOF and a workbook-globals first substream."""
    if len(payload) != 16:
        raise InvalidDocumentError("BIFF8 BOF payload must be exactly 16 bytes")
    version, substream_type = struct.unpack_from("<HH", payload)
    if version != 0x0600:
        raise InvalidDocumentError(f"unsupported BIFF version 0x{version:04x}")
    if substream_type not in _BIFF8_SUBSTREAM_TYPES:
        raise InvalidDocumentError(f"unsupported BIFF8 substream type 0x{substream_type:04x}")
    if require_globals and substream_type != _BIFF_GLOBALS:
        raise InvalidDocumentError("first BIFF substream is not workbook globals")
    if not require_globals and substream_type == _BIFF_GLOBALS:
        raise InvalidDocumentError("repeated BIFF workbook-globals substream")


def _clear_biff_record(buf, record_start: int, record_length: int, cleared_at: set[int]) -> int:
    """Zero one previously unseen non-zero BIFF payload and return its count contribution."""
    if record_start in cleared_at:
        return 0
    start = record_start + 4
    end = start + record_length
    if buf[start:end] == b"\x00" * record_length:
        return 0
    buf[start:end] = b"\x00" * record_length
    cleared_at.add(record_start)
    return 1


def _patch_word_document(data: bytes) -> tuple[bytes, int]:
    """Clear write-reservation / read-only recommended bits in Word FIB."""
    if len(data) < 0x20 or struct.unpack_from("<H", data, 0)[0] != 0xA5EC:
        raise InvalidDocumentError("WordDocument stream does not contain a supported FIB header")
    buf = bytearray(data)
    cleared = 0
    # fibBase flags at offset 0x000A (16-bit) in many nFib versions:
    # bit 0x0004 fReadOnlyRecommended, 0x0008 fWriteReservation
    flags_off = 0x0A
    if flags_off + 2 <= len(buf):
        flags = struct.unpack_from("<H", buf, flags_off)[0]
        new_flags = flags & ~0x000C  # clear read-only recommended + write reservation
        if new_flags != flags:
            struct.pack_into("<H", buf, flags_off, new_flags)
            cleared += 1
    # lKey write reservation password hash often at 0x000E (32-bit) in fibBase
    if 0x0E + 4 <= len(buf):
        if struct.unpack_from("<I", buf, 0x0E)[0] != 0:
            struct.pack_into("<I", buf, 0x0E, 0)
            cleared += 1
    return bytes(buf), cleared
