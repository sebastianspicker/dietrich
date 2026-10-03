"""Raw-bytes parsing of a PDF Standard-handler /Encrypt dictionary.

A tiny bounded tokenizer used as a fallback when pikepdf cannot open a file,
plus the field decoders that read typed values out of the parsed dictionary.
Operates only on an already size-limited buffer and performs no I/O. hash.py
turns these fields into a hash string.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass

from dietrich.errors import InvalidDocumentError
from dietrich.operation import checkpoint

MAX_PDF_DICTIONARY_DEPTH = 64
MAX_PDF_STRUCTURAL_ITEMS = 100_000
_LINE_END = re.compile(rb"[\r\n]")
_DIRECT_STREAM_LENGTH = re.compile(rb"/Length\s+(\d+)\s*(?:/|$)")


@dataclass(frozen=True)
class _DictionarySpan:
    """Offsets for one balanced PDF dictionary."""

    open_start: int
    body_start: int
    body_end: int


def find_encrypt_dict(raw: bytes) -> dict[str, str] | None:
    """Find a Standard-handler dictionary through one bounded structural index."""
    spans = _dictionary_spans(raw)
    starts = [span.open_start for span in spans]
    standard_starts = {span.open_start for span in spans if _is_standard_encrypt_span(raw, span)}
    trailer_dict = _trailer_encrypt_dict(raw, spans, starts, standard_starts)
    if trailer_dict is not None:
        return trailer_dict
    return _scan_standard_encrypt_dict(raw, spans, standard_starts)


def _trailer_encrypt_dict(
    raw: bytes,
    spans: list[_DictionarySpan],
    starts: list[int],
    standard_starts: set[int],
) -> dict[str, str] | None:
    """Resolve an inline or indirect Encrypt dictionary referenced by the trailer."""
    trailers = _bounded_matches(re.compile(rb"trailer"), raw, "trailer markers")
    references = _bounded_matches(
        re.compile(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R"), raw, "Encrypt references"
    )
    inline = _bounded_matches(re.compile(rb"/Encrypt\s*<<"), raw, "inline Encrypt values")
    objects = _object_headers(raw)
    reference_positions = [match.start() for match in references]
    inline_positions = [match.start() for match in inline]

    for trailer_match in reversed(trailers):
        marker_start = trailer_match.start()
        marker_end = marker_start + len(b"trailer")
        if not _has_keyword_boundaries(raw, marker_start, marker_end):
            continue
        trailer_span = _first_span_after(spans, starts, marker_end)
        if trailer_span is None:
            continue
        reference_index = bisect_left(reference_positions, trailer_span.body_start)
        if (
            reference_index < len(references)
            and references[reference_index].start() < trailer_span.body_end
        ):
            reference = references[reference_index]
            object_end = objects.get((int(reference.group(1)), int(reference.group(2))))
            object_span = (
                _first_span_after(spans, starts, object_end) if object_end is not None else None
            )
            if object_span is not None and object_span.open_start in standard_starts:
                return _parse_dict_body(raw[object_span.body_start : object_span.body_end])
        inline_index = bisect_left(inline_positions, trailer_span.body_start)
        if inline_index < len(inline) and inline[inline_index].start() < trailer_span.body_end:
            inline_span = _span_at_open(spans, starts, inline[inline_index].end() - 2)
            if inline_span is not None and inline_span.open_start in standard_starts:
                return _parse_dict_body(raw[inline_span.body_start : inline_span.body_end])
    return None


def _has_keyword_boundaries(raw: bytes, start: int, end: int) -> bool:
    """Return whether a matched PDF keyword is not embedded in another token."""
    word_bytes = b"_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return (start == 0 or raw[start - 1] not in word_bytes) and (
        end == len(raw) or raw[end] not in word_bytes
    )


def _scan_standard_encrypt_dict(
    raw: bytes, spans: list[_DictionarySpan], standard_starts: set[int]
) -> dict[str, str] | None:
    """Find the first dictionary that looks like a Standard security handler."""
    for span in spans:
        if span.open_start in standard_starts:
            return _parse_dict_body(raw[span.body_start : span.body_end])
    return None


def _is_standard_encrypt_span(raw: bytes, span: _DictionarySpan) -> bool:
    """Identify the minimally required Standard-handler dictionary tokens."""
    return all(
        raw.find(token, span.body_start, span.body_end) >= 0
        for token in (b"/Filter", b"/Standard", b"/O", b"/U")
    )


def _dictionary_spans(raw: bytes) -> list[_DictionarySpan]:
    """Index balanced dictionaries once while bounding nesting and item count."""
    spans: list[_DictionarySpan] = []
    stack: list[int] = []
    last_outer_span: _DictionarySpan | None = None
    opened = 0
    index = 0
    while index < len(raw):
        if index % 65_536 == 0:
            checkpoint()
        byte = raw[index]
        if not stack and raw.startswith(b"stream", index):
            keyword_end = index + len(b"stream")
            if _has_keyword_boundaries(raw, index, keyword_end):
                data_start = _stream_data_start(raw, keyword_end)
                if data_start is not None:
                    index = _stream_end(raw, data_start, last_outer_span)
                    continue
        if byte == ord("%"):
            index = _comment_end(raw, index)
            continue
        if stack and byte == ord("("):
            index = _skip_literal_string(raw, index)
            continue
        if byte == ord("<") and index + 1 < len(raw):
            if raw[index + 1] == ord("<"):
                opened += 1
                if opened > MAX_PDF_STRUCTURAL_ITEMS:
                    raise InvalidDocumentError("PDF contains too many dictionaries")
                if len(stack) >= MAX_PDF_DICTIONARY_DEPTH:
                    raise InvalidDocumentError(
                        f"PDF dictionary nesting exceeds {MAX_PDF_DICTIONARY_DEPTH} levels"
                    )
                stack.append(index)
                index += 2
                continue
            closing = raw.find(b">", index + 1)
            index = len(raw) if closing < 0 else closing + 1
            continue
        if byte == ord(">") and index + 1 < len(raw) and raw[index + 1] == ord(">"):
            if stack:
                start = stack.pop()
                span = _DictionarySpan(start, start + 2, index)
                spans.append(span)
                if not stack:
                    last_outer_span = span
            index += 2
            continue
        index += 1
    spans.sort(key=lambda span: span.open_start)
    return spans


def _comment_end(raw: bytes, start: int) -> int:
    """Return the offset after a PDF comment terminated by CR, LF, or CRLF."""
    match = _LINE_END.search(raw, start + 1)
    if match is None:
        return len(raw)
    end = match.start() + 1
    return end + 1 if raw[end - 1 : end + 1] == b"\r\n" else end


def _stream_data_start(raw: bytes, keyword_end: int) -> int | None:
    """Return the first byte after the required stream keyword line ending."""
    if raw[keyword_end : keyword_end + 2] == b"\r\n":
        return keyword_end + 2
    if raw[keyword_end : keyword_end + 1] in {b"\r", b"\n"}:
        return keyword_end + 1
    return None


def _stream_end(raw: bytes, data_start: int, dictionary: _DictionarySpan | None) -> int:
    """Skip opaque stream bytes using a direct bounded length when available."""
    if dictionary is not None:
        length_match = _DIRECT_STREAM_LENGTH.search(raw, dictionary.body_start, dictionary.body_end)
        if length_match is not None:
            declared_end = data_start + int(length_match.group(1))
            if declared_end > len(raw):
                raise InvalidDocumentError("PDF stream length exceeds the input")
            marker = raw.find(b"endstream", declared_end, min(len(raw), declared_end + 64))
            return marker + len(b"endstream") if marker >= 0 else declared_end
    marker = raw.find(b"endstream", data_start)
    return len(raw) if marker < 0 else marker + len(b"endstream")


def _skip_literal_string(raw: bytes, start: int) -> int:
    """Skip one PDF literal string, including escaped and nested parentheses."""
    depth = 1
    index = start + 1
    while index < len(raw) and depth:
        if raw[index] == ord("\\"):
            index += 2
            continue
        if raw[index] == ord("("):
            depth += 1
        elif raw[index] == ord(")"):
            depth -= 1
        index += 1
    return index


def _bounded_matches(pattern: re.Pattern[bytes], raw: bytes, label: str) -> list[re.Match[bytes]]:
    """Collect bounded structural matches from one linear regular-expression scan."""
    matches: list[re.Match[bytes]] = []
    for match in pattern.finditer(raw):
        if len(matches) >= MAX_PDF_STRUCTURAL_ITEMS:
            raise InvalidDocumentError(f"PDF contains too many {label}")
        matches.append(match)
    return matches


def _object_headers(raw: bytes) -> dict[tuple[int, int], int]:
    """Index the first offset after each indirect-object header."""
    pattern = re.compile(rb"(?<!\d)(\d+)\s+(\d+)\s+obj\b")
    headers: dict[tuple[int, int], int] = {}
    for match in _bounded_matches(pattern, raw, "indirect objects"):
        headers.setdefault((int(match.group(1)), int(match.group(2))), match.end())
    return headers


def _first_span_after(
    spans: list[_DictionarySpan], starts: list[int], offset: int
) -> _DictionarySpan | None:
    """Return the first indexed dictionary beginning at or after an offset."""
    index = bisect_left(starts, offset)
    return spans[index] if index < len(spans) else None


def _span_at_open(
    spans: list[_DictionarySpan], starts: list[int], offset: int
) -> _DictionarySpan | None:
    """Return the indexed dictionary with this exact opening offset."""
    index = bisect_left(starts, offset)
    if index < len(spans) and spans[index].open_start == offset:
        return spans[index]
    return None


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
