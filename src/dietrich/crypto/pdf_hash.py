"""Native PDF ``/Encrypt`` hash export for hashcat/john (no pdf2john required).

Parses Standard security handler fields and derives key bits from Length/CFM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, InvalidDocumentError
from dietrich.safety.bounded_io import read_file_limited

MAX_NATIVE_PDF_HASH_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class _PdfHashFields:
    """Normalized Standard-handler fields shared by PDF hash variants."""

    version: int | None
    permissions: int | None
    key_bits: int
    owner_hex: str
    user_hex: str
    file_id_hex: str


def export_pdf_hash(path: Path, fmt: str = "hashcat") -> str:
    """Build a crackable PDF hash line from the file's /Encrypt dictionary.

    Supports common revisions R=2,3,4 (RC4/AES-128) and R=5,6 (AES-256) where
    the on-disk /O /U /OE /UE /Perms fields are present.
    """
    path = Path(path)
    try:
        raw = read_file_limited(path, MAX_NATIVE_PDF_HASH_BYTES)
    except ValueError as exc:
        raise InvalidDocumentError(
            f"{path.name} exceeds the native PDF hash parser limit of "
            f"{MAX_NATIVE_PDF_HASH_BYTES} bytes"
        ) from exc
    if not raw.startswith(b"%PDF"):
        raise InvalidDocumentError(f"{path.name} is not a PDF")

    # Prefer pikepdf encryption params when available (handles modern writers).
    encrypt = _encrypt_dict_via_pikepdf(path) or _find_encrypt_dict(raw)
    if encrypt is None:
        raise EncryptedDocumentError(f"{path.name} has no /Encrypt dictionary")

    revision, fields = _pdf_hash_fields(path, raw, encrypt)

    if revision in {2, 3, 4}:
        hash_body = _legacy_pdf_hash(revision, fields)
    elif revision in {5, 6}:
        hash_body = _aes256_pdf_hash(path, encrypt, revision, fields)
    else:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported PDF revision R={revision} for native hash export"
        )

    if fmt == "john":
        return f"{path.name}:{hash_body}"
    return hash_body


def _pdf_hash_fields(
    path: Path, raw: bytes, encrypt: dict[str, str]
) -> tuple[int | None, _PdfHashFields]:
    """Validate shared Standard-handler fields used by every hash revision."""
    r = _int_field(encrypt, "R")
    v = _int_field(encrypt, "V")
    p = _int_field(encrypt, "P")
    length = _int_field(encrypt, "Length")
    filter_name = _name_field(encrypt, "Filter") or "Standard"
    if filter_name not in {"Standard", "StandardCrypt"}:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported security handler /Filter {filter_name}"
        )
    o_hex = _string_field_hex(encrypt, "O")
    u_hex = _string_field_hex(encrypt, "U")
    if not o_hex or not u_hex:
        raise EncryptedDocumentError(f"{path.name}: missing /O or /U in Encrypt dict")
    cfm = _name_field(encrypt, "CFM") or encrypt.get("CFM", "")
    bits = _pdf_key_bits(length=length, r=r, cfm=str(cfm))
    return r, _PdfHashFields(
        version=v,
        permissions=p,
        key_bits=bits,
        owner_hex=o_hex,
        user_hex=u_hex,
        file_id_hex=_file_id_hex(raw) or ("00" * 16),
    )


def _legacy_pdf_hash(revision: int, fields: _PdfHashFields) -> str:
    """Build the R2-R4 hashcat/john field sequence."""
    u_raw = bytes.fromhex(fields.user_hex)
    o_raw = bytes.fromhex(fields.owner_hex)
    id_raw = bytes.fromhex(fields.file_id_hex)
    u_use = u_raw[:32]
    o_use = o_raw[:32]
    return (
        f"$pdf${fields.version or 2}*{revision}*{fields.key_bits}*"
        f"{fields.permissions if fields.permissions is not None else 0}*0*"
        f"{len(id_raw)}*{id_raw.hex()}*{len(u_use)}*{u_use.hex()}*{len(o_use)}*{o_use.hex()}"
    )


def _aes256_pdf_hash(
    path: Path,
    encrypt: dict[str, str],
    revision: int,
    fields: _PdfHashFields,
) -> str:
    """Build the R5-R6 AES-256 hashcat/john field sequence."""
    oe = _string_field_hex(encrypt, "OE")
    ue = _string_field_hex(encrypt, "UE")
    perms = _string_field_hex(encrypt, "Perms")
    if not (oe and ue and perms):
        raise EncryptedDocumentError(
            f"{path.name}: R={revision} requires /OE /UE /Perms for hash export"
        )
    return (
        f"$pdf${fields.version or 5}*{revision}*256*"
        f"{fields.permissions if fields.permissions is not None else 0}*1*"
        f"16*{fields.file_id_hex[:32]}*127*{fields.user_hex[:254]}*"
        f"127*{fields.owner_hex[:254]}*"
        f"32*{ue[:64]}*32*{oe[:64]}*16*{perms[:32]}"
    )


def _pdf_key_bits(*, length: int | None, r: int | None, cfm: str) -> int:
    """Derive key length in bits for PDF hash export.

    PDF /Length is often in bytes for crypt filters (16 → 128-bit AES).
    Legacy RC4 uses bit lengths 40/128 directly.
    """
    cfm_u = cfm.upper().replace("/", "")
    if "AESV3" in cfm_u or (r is not None and r >= 5):
        return 256
    if "AESV2" in cfm_u or "AES" in cfm_u:
        return _aes_key_bits(length)
    return _rc4_key_bits(length, r)


def _aes_key_bits(length: int | None) -> int:
    """Interpret PDF AES key length, which may be stored in bytes."""
    if length is None:
        return 128
    return length * 8 if length <= 32 else length


def _rc4_key_bits(length: int | None, revision: int | None) -> int:
    """Interpret legacy RC4 lengths while retaining their small-value convention."""
    if length is None:
        return 40 if revision is None or revision <= 2 else 128
    if length in {5, 16}:
        return length * 8
    return length


def _encrypt_dict_via_pikepdf(path: Path) -> dict[str, str] | None:
    """Extract /Encrypt dict fields via pikepdf when possible."""
    try:
        import pikepdf
    except ImportError:
        return None
    return _pikepdf_encrypt_or_raw(path, pikepdf)


def _pikepdf_encrypt_or_raw(path: Path, pikepdf) -> dict[str, str] | None:
    """Use pikepdf when it can open the file, otherwise retain raw-trailer fallback."""
    try:
        pdf = pikepdf.open(path)
    except (pikepdf.PasswordError, pikepdf.PdfError, OSError, TypeError, ValueError):
        return _encrypt_from_raw_trailer(path)
    try:
        return _opened_pikepdf_encrypt_dict(pdf, pikepdf)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return _encrypt_from_raw_trailer(path)
    finally:
        pdf.close()


def _opened_pikepdf_encrypt_dict(pdf, pikepdf) -> dict[str, str] | None:
    """Extract encryption fields from an already-open pikepdf document."""
    if not pdf.is_encrypted:
        return None
    encrypt = pdf.trailer.get("/Encrypt")
    if encrypt is None:
        return None
    result = _pikepdf_encrypt_fields(pikepdf, encrypt)
    return result if "O" in result and "U" in result else None


def _pikepdf_encrypt_fields(pikepdf, encrypt) -> dict[str, str]:
    """Normalize pikepdf's encryption dictionary into raw-token strings."""
    encrypt = _pikepdf_object(encrypt)
    result = _pikepdf_scalar_fields(pikepdf, encrypt)
    result.update(_pikepdf_binary_fields(pikepdf, encrypt))
    _add_pikepdf_crypt_filter(pikepdf, encrypt, result)
    return result


def _pikepdf_object(value):
    """Dereference a pikepdf indirect object when necessary."""
    return value.get_object() if hasattr(value, "get_object") else value


def _pikepdf_item(pikepdf, mapping, key: str):
    """Read a PDF name with pikepdf and string-key compatibility."""
    for candidate in (pikepdf.Name(f"/{key}"), f"/{key}"):
        try:
            return mapping[candidate]
        except (KeyError, TypeError):
            continue
    return None


def _pikepdf_scalar_fields(pikepdf, encrypt) -> dict[str, str]:
    """Extract scalar revision, permission, length, and filter fields."""
    result: dict[str, str] = {}
    for key in ("R", "V", "P", "Length", "Filter"):
        value = _pikepdf_item(pikepdf, encrypt, key)
        if value is None:
            continue
        if key in {"R", "V", "P", "Length"}:
            result[key] = str(int(value))
        else:
            result[key] = str(value).lstrip("/")
    return result


def _pikepdf_binary_fields(pikepdf, encrypt) -> dict[str, str]:
    """Extract binary encryption fields as PDF-style hex strings."""
    result: dict[str, str] = {}
    for key in ("O", "U", "OE", "UE", "Perms"):
        value = _pikepdf_item(pikepdf, encrypt, key)
        if value is None:
            continue
        try:
            result[key] = "<" + bytes(value).hex() + ">"
        except (TypeError, ValueError):
            continue
    return result


def _add_pikepdf_crypt_filter(pikepdf, encrypt, result: dict[str, str]) -> None:
    """Capture optional AES crypt-filter metadata without blocking raw fallback."""
    crypt_filters = _pikepdf_item(pikepdf, encrypt, "CF")
    if crypt_filters is None:
        return
    try:
        standard = _pikepdf_item(pikepdf, _pikepdf_object(crypt_filters), "StdCF")
        if standard is None:
            return
        standard = _pikepdf_object(standard)
        cfm = _pikepdf_item(pikepdf, standard, "CFM")
        if cfm is not None:
            result["CFM"] = str(cfm).lstrip("/")
        if "Length" not in result:
            length = _pikepdf_item(pikepdf, standard, "Length")
            if length is not None:
                result["Length"] = str(int(length))
    except (AttributeError, KeyError, TypeError, ValueError):
        return


def _encrypt_from_raw_trailer(path: Path) -> dict[str, str] | None:
    """Fallback: parse /Encrypt from raw PDF trailer bytes."""
    return _find_encrypt_dict(path.read_bytes())


def _find_encrypt_dict(raw: bytes) -> dict[str, str] | None:
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
    # Normalize
    result: dict[str, str] = {}
    # Names
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s*/([A-Za-z0-9_+-]+)", text):
        result.setdefault(m.group(1), "/" + m.group(2))
    # Integers
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s+(-?\d+)", text):
        result.setdefault(m.group(1), m.group(2))
    # Hex strings <...>
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s*<([0-9A-Fa-f\s]+)>", text):
        result[m.group(1)] = "<" + re.sub(r"\s+", "", m.group(2)) + ">"
    # Literal strings ( ... ) with basic escapes - crude
    for m in re.finditer(r"/([A-Za-z0-9_]+)\s\((?:\\.|[^\\)])\)", text):
        full = m.group(0)
        key = m.group(1)
        val = full[full.index("(") :]
        result[key] = val
    return result


def _int_field(d: dict[str, str], key: str) -> int | None:
    """Parse an integer PDF dictionary field by name."""
    v = d.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


def _name_field(d: dict[str, str], key: str) -> str | None:
    """Parse a name PDF dictionary field (e.g. /AESV2)."""
    v = d.get(key)
    if v is None:
        return None
    return v.lstrip("/")


def _string_field_hex(d: dict[str, str], key: str) -> str | None:
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


def _file_id_hex(raw: bytes) -> str | None:
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
