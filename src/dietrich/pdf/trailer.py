"""Raw-bytes parsing of a PDF Standard-handler /Encrypt dictionary.

A tiny bounded tokenizer used as a fallback when pikepdf cannot open a file,
plus the field decoders that read typed values out of the parsed dictionary.
Operates only on an already size-limited buffer, performs no I/O, and depends
only on the standard library. hash.py turns these fields into a hash string.
"""

from __future__ import annotations

import re


def find_encrypt_dict(raw: bytes) -> dict[str, str] | None:
    """Very small PDF tokenizer: find /Encrypt dict body as key→value strings."""
    trailer_dict = _trailer_encrypt_dict(raw)
    if trailer_dict is not None:
        return trailer_dict
    return _scan_standard_encrypt_dict(raw)


def _trailer_encrypt_dict(raw: bytes) -> dict[str, str] | None:
    """Resolve an inline or indirect Encrypt dictionary referenced by the trailer."""
    search_end = len(raw)
    while (marker_start := raw.rfind(b"trailer", 0, search_end)) >= 0:
        search_end = marker_start
        marker_end = marker_start + len(b"trailer")
        if not _has_keyword_boundaries(raw, marker_start, marker_end):
            continue
        body = _extract_balanced_dict(raw, marker_end)
        if body is None:
            continue
        reference = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", body)
        if reference is not None:
            parsed = _referenced_encrypt_dict(
                raw,
                int(reference.group(1)),
                int(reference.group(2)),
            )
            if parsed is not None:
                return parsed
        if re.search(rb"/Encrypt\s*<<", body):
            parsed = _parse_dict_body(_extract_inline_dict(body, b"/Encrypt"))
            if parsed:
                return parsed
    return None


def _has_keyword_boundaries(raw: bytes, start: int, end: int) -> bool:
    """Return whether a matched PDF keyword is not embedded in another token."""
    word_bytes = b"_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return (start == 0 or raw[start - 1] not in word_bytes) and (
        end == len(raw) or raw[end] not in word_bytes
    )


def _referenced_encrypt_dict(
    raw: bytes, object_number: int, generation: int
) -> dict[str, str] | None:
    """Read a trailer-referenced dictionary only when it has Standard hash fields."""
    match = re.search(rf"{object_number}\s+{generation}\s+obj".encode(), raw)
    if match is None:
        return None
    body = _extract_balanced_dict(raw, match.end())
    if body is None:
        return None
    parsed = _parse_dict_body(body)
    return parsed if "O" in parsed and "U" in parsed else None


def _scan_standard_encrypt_dict(raw: bytes) -> dict[str, str] | None:
    """Find the first dictionary that looks like a Standard security handler."""
    for m in re.finditer(rb"<<", raw):
        body = _extract_balanced_dict(raw, m.start())
        if body is not None and _is_standard_encrypt_dict(body):
            return _parse_dict_body(body)
    return None


def _is_standard_encrypt_dict(body: bytes) -> bool:
    """Identify the minimally required Standard-handler dictionary tokens."""
    return all(token in body for token in (b"/Filter", b"/Standard", b"/O", b"/U"))


def _extract_balanced_dict(raw: bytes, start: int) -> bytes | None:
    """From start (at or before '<<'), return inner body of balanced <<...>>."""
    i = raw.find(b"<<", start)
    if i < 0:
        return None
    depth = 0
    j = i
    while j < len(raw) - 1:
        if raw[j : j + 2] == b"<<":
            depth += 1
            j += 2
            continue
        if raw[j : j + 2] == b">>":
            depth -= 1
            j += 2
            if depth == 0:
                return raw[i + 2 : j - 2]
            continue
        j += 1
    return None


def _extract_inline_dict(trailer_body: bytes, key: bytes) -> bytes:
    """Extract a balanced <<…>> dict starting at offset."""
    idx = trailer_body.find(key)
    if idx < 0:
        return b""
    rest = trailer_body[idx + len(key) :]
    start = rest.find(b"<<")
    if start < 0:
        return b""
    depth = 0
    for i in range(start, len(rest) - 1):
        if rest[i : i + 2] == b"<<":
            depth += 1
        elif rest[i : i + 2] == b">>":
            depth -= 1
            if depth == 0:
                return rest[start + 2 : i]
    return b""


def _parse_dict_body(body: bytes) -> dict[str, str]:
    """Parse PDF dict body into coarse string values (keys without slash)."""
    text = body.decode("latin-1", errors="latin-1")
    result: dict[str, str] = {}
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s*/([A-Za-z0-9_+-]+)", text):
        result.setdefault(m.group(1), "/" + m.group(2))
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s+(-?\d+)", text):
        result.setdefault(m.group(1), m.group(2))
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s*<([0-9A-Fa-f\s]+)>", text):
        result[m.group(1)] = "<" + re.sub(r"\s+", "", m.group(2)) + ">"
    # Only the simple literal strings used by supported handlers are accepted here.
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s\((?:\\.|[^\\)])\)", text):
        full = m.group(0)
        key = m.group(1)
        val = full[full.index("(") :]
        result[key] = val
    return result


def int_field(d: dict[str, str], key: str) -> int | None:
    """Parse an integer PDF dictionary field by name."""
    v = d.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def name_field(d: dict[str, str], key: str) -> str | None:
    """Parse a name PDF dictionary field (e.g. /AESV2)."""
    v = d.get(key)
    if v is None:
        return None
    return v.lstrip("/")


def string_field_hex(d: dict[str, str], key: str) -> str | None:
    """Parse a PDF string field to hex for hash export."""
    value = d.get(key)
    if value is None:
        return None
    if value.startswith("<") and value.endswith(">"):
        return value[1:-1].lower()
    return _literal_string_hex(value) if value.startswith("(") and value.endswith(")") else None


def _literal_string_hex(value: str) -> str | None:
    """Decode a PDF literal string's basic escapes into its hash bytes."""
    raw = value.encode("latin-1")
    try:
        payload = raw[raw.index(b"(") + 1 : raw.rindex(b")")]
    except ValueError:
        return None
    return _decode_pdf_literal(payload).hex()


def _decode_pdf_literal(payload: bytes) -> bytes:
    """Decode literal bytes, named escapes, and up to three-digit octal escapes."""
    output = bytearray()
    index = 0
    while index < len(payload):
        byte, index = _decode_pdf_literal_byte(payload, index)
        if byte is not None:
            output.append(byte)
    return bytes(output)


def _decode_pdf_literal_byte(payload: bytes, index: int) -> tuple[int | None, int]:
    """Decode one plain or backslash-escaped literal byte."""
    if payload[index] != 0x5C or index + 1 >= len(payload):
        return payload[index], index + 1
    escaped = payload[index + 1]
    named = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    if escaped in named:
        return named[escaped], index + 2
    if escaped in (0x0A, 0x0D):
        return None, _line_continuation_end(payload, index, escaped)
    if 0x30 <= escaped <= 0x37:
        return _decode_octal_escape(payload, index + 1)
    return escaped, index + 2


def _line_continuation_end(payload: bytes, index: int, escaped: int) -> int:
    """Skip one escaped PDF line ending, including a CRLF pair."""
    if escaped == 0x0D and index + 2 < len(payload) and payload[index + 2] == 0x0A:
        return index + 3
    return index + 2


def _decode_octal_escape(payload: bytes, start: int) -> tuple[int, int]:
    """Decode a one-to-three digit octal escape starting at an octal byte."""
    end = start
    while end < len(payload) and end - start < 3 and 0x30 <= payload[end] <= 0x37:
        end += 1
    return int(payload[start:end], 8) & 0xFF, end


def file_id_hex(raw: bytes) -> str | None:
    """Return the first PDF /ID string as normalized hexadecimal bytes."""
    match = re.search(rb"/ID\s*\[\s*", raw)
    if match is None or match.end() >= len(raw):
        return None
    start = match.end()
    if raw[start] == ord("<"):
        return _hex_file_id(raw, start)
    if raw[start] == ord("("):
        payload = _literal_payload(raw, start)
        return _decode_pdf_literal(payload).hex() if payload is not None else None
    return None


def _hex_file_id(raw: bytes, start: int) -> str | None:
    """Normalize the first angle-bracket PDF file identifier."""
    end = raw.find(b">", start + 1)
    if end < 0:
        return None
    compact = raw[start + 1 : end].translate(None, b"\x00\t\n\x0c\r ")
    if not compact or re.fullmatch(rb"[0-9A-Fa-f]+", compact) is None:
        return None
    if len(compact) % 2:
        compact += b"0"
    return compact.decode("ascii").lower()


def _literal_payload(raw: bytes, start: int) -> bytes | None:
    """Extract one balanced PDF literal string while retaining escape bytes."""
    depth = 1
    index = start + 1
    while index < len(raw):
        byte = raw[index]
        if byte == 0x5C:
            index += 2
            continue
        if byte == ord("("):
            depth += 1
        elif byte == ord(")"):
            depth -= 1
            if depth == 0:
                return raw[start + 1 : index]
        index += 1
    return None


__all__ = [
    "file_id_hex",
    "find_encrypt_dict",
    "int_field",
    "name_field",
    "string_field_hex",
]
