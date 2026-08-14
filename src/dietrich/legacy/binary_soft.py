"""Soft structure-protection rewrite for binary Office (``.xls``/``.doc``/``.ppt``).

Patches OLE streams in place (equal length) to clear BIFF/FIB protect records.
Does not open-password decrypt - that is the msoffcrypto hard path.
"""

from __future__ import annotations

import shutil
import struct
from collections.abc import Iterator
from pathlib import Path

from dietrich.errors import InvalidDocumentError, OutputExistsError, UnsupportedFormatError
from dietrich.legacy.cfb_io import patch_streams, read_streams
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.types import DocumentFormat, RemovalCounts, UnlockOptions, UnlockResult

# BIFF record types related to protection (Excel)
_BIFF_PROTECT = 0x0012
_BIFF_PASSWORD = 0x0013
_BIFF_WINDOW_PROTECT = 0x0019
_BIFF_OBJ_PROTECT = 0x0063
_BIFF_SCEN_PROTECT = 0x00DD
_BIFF_PROT4REV = 0x01AF
_BIFF_PROT4REVPASS = 0x01BC
_BIFF_SHEETPROTECTION = 0x0867  # FeatHdr related - also scan Feat


def unlock_binary_office(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions | None = None,
) -> UnlockResult:
    """Soft-unlock binary Office CFBF files (.xls/.doc/.ppt)."""
    options = options or UnlockOptions()
    source = Path(input_path)
    target = Path(output_path)

    if target.exists() and not options.overwrite:
        raise OutputExistsError(f"{target} already exists.")

    try:
        streams = read_streams(source)
    except Exception as exc:
        raise InvalidDocumentError(f"{source} is not a readable OLE/CFB file: {exc}") from exc

    patches, counts = _build_patches(source, streams)

    with temporary_output_path(target) as temp_path:
        if not patches:
            # Still write a copy so output exists; zero removals.
            shutil.copy2(source, temp_path)
            warnings = ("No binary protection records found; wrote unchanged copy.",)
            result_counts = RemovalCounts()
        else:
            try:
                patch_streams(source, temp_path, patches)
            except Exception as exc:
                raise InvalidDocumentError(f"failed to write patched OLE: {exc}") from exc
            warnings = ("Soft-cleared binary Office protection records.",)
            result_counts = counts

        try:
            read_streams(temp_path)
        except Exception as exc:
            raise InvalidDocumentError(f"patched OLE failed validation: {exc}") from exc

        publish_output(temp_path, target, overwrite=options.overwrite)

    return UnlockResult(
        input_path=source,
        output_path=target,
        removed=result_counts,
        document_format=DocumentFormat.LEGACY_CFBF,
        warnings=warnings,
    )


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
    for table_name in ("0Table", "1Table"):
        table_key = _find_stream(streams, table_name)
        if table_key is None:
            continue
        table_data, table_count = _patch_word_table_protection(streams[table_key])
        if table_count:
            patches[table_key] = table_data
            count += table_count
    return patches, RemovalCounts(document_protections=count)


def _patch_ppt_streams(
    source: Path, streams: dict[str, bytes]
) -> tuple[dict[str, bytes], RemovalCounts]:
    """Patch PowerPoint Document modify-verifier records."""
    key = _find_stream(streams, "PowerPoint Document")
    if not key:
        raise UnsupportedFormatError(f"{source.name}: no PowerPoint Document stream")
    data, count = _patch_ppt_document(streams[key])
    if not count:
        return {}, RemovalCounts()
    return {key: data}, RemovalCounts(modify_verifiers=count)


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
    cleared += _scan_biff_protection_markers(buf, protection_lengths, cleared_at)
    return bytes(buf), cleared


def _walk_biff_protection_records(buf, protection_lengths, cleared_at: set[int]) -> int:
    """Clear aligned BIFF protection records from a well-formed record walk."""
    cleared = 0
    index = 0
    while index + 4 <= len(buf):
        record_type, record_length = struct.unpack_from("<HH", buf, index)
        end = index + 4 + record_length
        if record_length > 100_000 or end > len(buf):
            break
        if record_length in protection_lengths.get(record_type, set()):
            cleared += _clear_biff_record(buf, index, record_length, cleared_at)
        index = end
    return cleared


def _scan_biff_protection_markers(buf, protection_lengths, cleared_at: set[int]) -> int:
    """Clear valid protection markers that appear in malformed or injected streams."""
    return sum(
        _clear_biff_marker_matches(buf, record_type, length, cleared_at)
        for record_type, length in _biff_marker_specs(protection_lengths)
    )


def _biff_marker_specs(protection_lengths) -> Iterator[tuple[int, int]]:
    """Yield protection record type and payload-length combinations to scan."""
    for record_type, lengths in protection_lengths.items():
        for length in lengths:
            yield record_type, length


def _clear_biff_marker_matches(buf, record_type: int, length: int, cleared_at: set[int]) -> int:
    """Clear conservative matches for one BIFF header shape."""
    return sum(
        _clear_biff_record(buf, index, length, cleared_at)
        for index in _clearable_biff_marker_offsets(buf, record_type, length)
    )


def _clearable_biff_marker_offsets(buf, record_type: int, length: int) -> Iterator[int]:
    """Yield valid, non-zero protection records for a marker header."""
    marker = struct.pack("<HH", record_type, length)
    start = 0
    while (index := buf.find(marker, start)) >= 0:
        payload_end = index + 4 + length
        if payload_end > len(buf):
            return
        payload = buf[index + 4 : payload_end]
        if _is_clearable_biff_payload(payload, record_type):
            yield index
        start = index + 2


def _is_clearable_biff_payload(payload: bytes, record_type: int) -> bool:
    """Keep marker scanning conservative for boolean rather than password records."""
    payload = bytes(payload)
    if payload == b"\x00" * len(payload):
        return False
    if record_type == _BIFF_PASSWORD:
        return True
    return payload in {b"\x01\x00", b"\x00\x01"}


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
    if len(data) < 0x20:
        return data, 0
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
    # Also clear any "Password" UTF-16 occurrences used by some protectors (rare)
    return bytes(buf), cleared


def _patch_word_table_protection(data: bytes) -> tuple[bytes, int]:
    """Best-effort: zero short password-hash-like fields near 'Prot' markers."""
    buf = bytearray(data)
    cleared = 0
    # Look for Sprm or opcode patterns is complex; zero 2-byte non-zero runs after b'Prot'
    needle = b"Prot"
    start = 0
    while True:
        idx = buf.find(needle, start)
        if idx < 0:
            break
        # zero next 16 bytes after marker if within bounds (hash storage guess)
        for j in range(idx + 4, min(idx + 20, len(buf))):
            if buf[j] != 0:
                buf[j] = 0
                cleared += 1
        start = idx + 4
    return bytes(buf), cleared


def _patch_ppt_document(data: bytes) -> tuple[bytes, int]:
    """Best-effort PowerPoint binary protection clear.

    Looks for known protect-related atom markers and zeros small hash fields.
    """
    buf = bytearray(data)
    cleared = _clear_ppt_text_markers(buf)
    cleared += _clear_ppt_protection_atoms(buf)
    return bytes(buf), cleared


def _clear_ppt_text_markers(buf) -> int:
    """Zero the short fields following recognizable PowerPoint protection labels."""
    cleared = 0
    for needle in (b"Protect", b"Password", b"Modify"):
        start = 0
        while True:
            index = buf.find(needle, start)
            if index < 0:
                break
            cleared += _zero_ppt_window(buf, index, len(needle))
            start = index + len(needle)
    return cleared


def _zero_ppt_window(buf, index: int, marker_length: int) -> int:
    """Clear non-zero bytes after a marker within its original 32-byte window."""
    cleared = 0
    for position in range(index + marker_length, min(index + 32, len(buf))):
        if buf[position] != 0:
            buf[position] = 0
            cleared += 1
    return cleared


def _clear_ppt_protection_atoms(buf) -> int:
    """Clear short known protection atoms while walking plausible record headers."""
    cleared = 0
    index = 0
    while index + 8 <= len(buf):
        record_type = struct.unpack_from("<H", buf, index + 2)[0]
        record_length = struct.unpack_from("<I", buf, index + 4)[0]
        if record_length > len(buf) or record_length > 10_000_000:
            index += 2
            continue
        if record_type in {0x0FF5, 0x0FF6, 0x101D} and 0 < record_length <= 64:
            cleared += _zero_ppt_atom(buf, index + 8, record_length)
        index += 8 + record_length if record_length < 1_000_000 else 2
    return cleared


def _zero_ppt_atom(buf, start: int, length: int) -> int:
    """Clear non-zero payload bytes from one short PowerPoint settings atom."""
    cleared = 0
    for position in range(start, min(start + length, len(buf))):
        if buf[position] != 0:
            buf[position] = 0
            cleared += 1
    return cleared
