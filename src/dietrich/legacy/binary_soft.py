"""Soft structure-protection rewrite for binary Office (``.xls``/``.doc``/``.ppt``).

Patches OLE streams in place (equal length) to clear BIFF/FIB protect records.
Does not open-password decrypt - that is the msoffcrypto hard path.
"""

from __future__ import annotations

import struct
from pathlib import Path

from dietrich.errors import InvalidDocumentError, UnsupportedFormatError
from dietrich.legacy.cfb_io import patch_streams, read_streams
from dietrich.types import RemovalCounts, UnlockOptions, UnlockResult

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
        from dietrich.errors import OutputExistsError

        raise OutputExistsError(f"{target} already exists.")

    try:
        streams = read_streams(source)
    except Exception as exc:
        raise InvalidDocumentError(f"{source} is not a readable OLE/CFB file: {exc}") from exc

    kind = _detect_kind(streams)
    patches: dict[str, bytes] = {}
    counts = RemovalCounts()

    if kind == "xls":
        key = _find_stream(streams, "Workbook") or _find_stream(streams, "Book")
        if not key:
            raise UnsupportedFormatError(f"{source.name}: no Workbook stream")
        new_data, n = _patch_biff_workbook(streams[key])
        if n:
            patches[key] = new_data
            counts = RemovalCounts(worksheet_protections=n)
    elif kind == "doc":
        key = _find_stream(streams, "WordDocument")
        if not key:
            raise UnsupportedFormatError(f"{source.name}: no WordDocument stream")
        new_data, n = _patch_word_document(streams[key])
        if n:
            patches[key] = new_data
            counts = RemovalCounts(document_protections=n)
        # Table stream may hold section protection - best-effort scan
        for tname in ("0Table", "1Table"):
            tkey = _find_stream(streams, tname)
            if tkey:
                td, tn = _patch_word_table_protection(streams[tkey])
                if tn:
                    patches[tkey] = td
                    counts = RemovalCounts(document_protections=counts.document_protections + tn)
    elif kind == "ppt":
        key = _find_stream(streams, "PowerPoint Document")
        if not key:
            raise UnsupportedFormatError(f"{source.name}: no PowerPoint Document stream")
        new_data, n = _patch_ppt_document(streams[key])
        if n:
            patches[key] = new_data
            counts = RemovalCounts(modify_verifiers=n)
    else:
        raise UnsupportedFormatError(
            f"{source.name}: unrecognized binary Office streams "
            f"(found: {', '.join(sorted(streams)[:8])})"
        )

    from dietrich.types import DocumentFormat

    if not patches:
        # Still write a copy so output exists; zero removals
        target.write_bytes(source.read_bytes())
        return UnlockResult(
            input_path=source,
            output_path=target,
            removed=RemovalCounts(),
            document_format=DocumentFormat.LEGACY_CFBF,
            warnings=("No binary protection records found; wrote unchanged copy.",),
        )

    try:
        patch_streams(source, target, patches)
    except Exception as exc:
        raise InvalidDocumentError(f"failed to write patched OLE: {exc}") from exc

    # Verify readable
    try:
        read_streams(target)
    except Exception as exc:
        raise InvalidDocumentError(f"patched OLE failed validation: {exc}") from exc

    return UnlockResult(
        input_path=source,
        output_path=target,
        removed=counts,
        document_format=DocumentFormat.LEGACY_CFBF,
        warnings=("Soft-cleared binary Office protection records.",),
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
    records_cleared = 0
    # type -> allowed payload lengths
    protect_lens = {
        _BIFF_PROTECT: {2},
        _BIFF_PASSWORD: {2},
        _BIFF_WINDOW_PROTECT: {2},
        _BIFF_OBJ_PROTECT: {2},
        _BIFF_SCEN_PROTECT: {2},
        _BIFF_PROT4REV: {2},
        _BIFF_PROT4REVPASS: {2},
    }
    # Track cleared record starts to avoid double-count
    cleared_at: set[int] = set()

    def clear_record(rec_start: int, rec_len: int) -> None:
        """Zero one BIFF protection record payload; count once per record start."""
        nonlocal records_cleared
        if rec_start in cleared_at:
            return
        data_start = rec_start + 4
        data_end = data_start + rec_len
        # Only count if payload had something to clear (protect flag or hash)
        payload = buf[data_start:data_end]
        if payload == b"\x00" * rec_len:
            return
        for j in range(data_start, data_end):
            buf[j] = 0
        cleared_at.add(rec_start)
        records_cleared += 1

    # Sequential BIFF walk (aligned records)
    i = 0
    while i + 4 <= len(buf):
        rec_type = struct.unpack_from("<H", buf, i)[0]
        rec_len = struct.unpack_from("<H", buf, i + 2)[0]
        data_end = i + 4 + rec_len
        if rec_len > 100_000 or data_end > len(buf):
            break
        allowed = protect_lens.get(rec_type)
        if allowed is not None and rec_len in allowed:
            clear_record(i, rec_len)
        i = data_end

    # Secondary: exact type+len markers with non-zero payload only (mid-stream injects)
    for rec_type, allowed in protect_lens.items():
        for exp in allowed:
            marker = struct.pack("<HH", rec_type, exp)
            start = 0
            while True:
                idx = buf.find(marker, start)
                if idx < 0 or idx + 4 + exp > len(buf):
                    break
                payload = bytes(buf[idx + 4 : idx + 4 + exp])
                if payload != b"\x00" * exp:
                    # Boolean protect flags are 0/1; password is any non-zero hash
                    if rec_type != _BIFF_PASSWORD and payload not in {
                        b"\x01\x00",
                        b"\x00\x01",
                    }:
                        start = idx + 2
                        continue
                    clear_record(idx, exp)
                start = idx + 2

    return bytes(buf), records_cleared


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
    cleared = 0
    # PowerPoint records: version/instance/type/length - type is 16-bit at offset+2
    # Search for password/protect string markers
    for needle in (b"Protect", b"Password", b"Modify"):
        start = 0
        while True:
            idx = buf.find(needle, start)
            if idx < 0:
                break
            for j in range(idx, min(idx + 32, len(buf))):
                if buf[j] != 0 and j >= idx + len(needle):
                    buf[j] = 0
                    cleared += 1
            start = idx + len(needle)
    # Also walk simple atom headers and zero records that look like 2-byte protect flags
    i = 0
    while i + 8 <= len(buf):
        # recVer/recInstance (2) + recType (2) + recLen (4)
        rec_type = struct.unpack_from("<H", buf, i + 2)[0]
        rec_len = struct.unpack_from("<I", buf, i + 4)[0]
        if rec_len > len(buf) or rec_len > 10_000_000:
            i += 2
            continue
        # Heuristic types sometimes used for doc settings
        if rec_type in {0x0FF5, 0x0FF6, 0x101D} and 0 < rec_len <= 64:
            for j in range(i + 8, min(i + 8 + rec_len, len(buf))):
                if buf[j] != 0:
                    buf[j] = 0
                    cleared += 1
        i += 8 + rec_len if rec_len < 1_000_000 else 2
    return bytes(buf), cleared
