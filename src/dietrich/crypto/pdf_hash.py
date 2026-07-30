"""Native PDF ``/Encrypt`` hash export for hashcat/john (no pdf2john required).

Parses Standard security handler fields and derives key bits from Length/CFM.
"""

from __future__ import annotations

import re
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, InvalidDocumentError


def export_pdf_hash(path: Path, fmt: str = "hashcat") -> str:
    """Build a crackable PDF hash line from the file's /Encrypt dictionary.

    Supports common revisions R=2,3,4 (RC4/AES-128) and R=5,6 (AES-256) where
    the on-disk /O /U /OE /UE /Perms fields are present.
    """
    path = Path(path)
    raw = path.read_bytes()
    if not raw.startswith(b"%PDF"):
        raise InvalidDocumentError(f"{path.name} is not a PDF")

    # Prefer pikepdf encryption params when available (handles modern writers).
    encrypt = _encrypt_dict_via_pikepdf(path) or _find_encrypt_dict(raw)
    if encrypt is None:
        raise EncryptedDocumentError(f"{path.name} has no /Encrypt dictionary")

    r, v, p, bits, o_hex, u_hex, id_hex = _pdf_hash_fields(path, raw, encrypt)

    if r in {2, 3, 4}:
        hash_body = _legacy_pdf_hash(r, v, p, bits, o_hex, u_hex, id_hex)
    elif r in {5, 6}:
        hash_body = _aes256_pdf_hash(path, encrypt, r, v, p, o_hex, u_hex, id_hex)
    else:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported PDF revision R={r} for native hash export"
        )

    if fmt == "john":
        return f"{path.name}:{hash_body}"
    return hash_body


def _pdf_hash_fields(
    path: Path, raw: bytes, encrypt: dict[str, str]
) -> tuple[int | None, int | None, int | None, int, str, str, str]:
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
    return r, v, p, bits, o_hex, u_hex, _file_id_hex(raw) or ("00" * 16)


def _legacy_pdf_hash(
    r: int,
    v: int | None,
    p: int | None,
    bits: int,
    o_hex: str,
    u_hex: str,
    id_hex: str,
) -> str:
    """Build the R2-R4 hashcat/john field sequence."""
    u_raw = bytes.fromhex(u_hex)
    o_raw = bytes.fromhex(o_hex)
    id_raw = bytes.fromhex(id_hex)
    u_use = u_raw[:32]
    o_use = o_raw[:32]
    return (
        f"$pdf${v or 2}*{r}*{bits}*{p if p is not None else 0}*0*"
        f"{len(id_raw)}*{id_raw.hex()}*{len(u_use)}*{u_use.hex()}*{len(o_use)}*{o_use.hex()}"
    )


def _aes256_pdf_hash(
    path: Path,
    encrypt: dict[str, str],
    r: int,
    v: int | None,
    p: int | None,
    o_hex: str,
    u_hex: str,
    id_hex: str,
) -> str:
    """Build the R5-R6 AES-256 hashcat/john field sequence."""
    oe = _string_field_hex(encrypt, "OE")
    ue = _string_field_hex(encrypt, "UE")
    perms = _string_field_hex(encrypt, "Perms")
    if not (oe and ue and perms):
        raise EncryptedDocumentError(f"{path.name}: R={r} requires /OE /UE /Perms for hash export")
    return (
        f"$pdf${v or 5}*{r}*256*{p if p is not None else 0}*1*"
        f"16*{id_hex[:32]}*127*{u_hex[:254]}*127*{o_hex[:254]}*"
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
        pdf = pikepdf.open(path, password="")
    except pikepdf.PasswordError:
        return _encrypt_from_raw_trailer(path)
    except (OSError, TypeError, ValueError):
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
    try:
        return mapping[pikepdf.Name(f"/{key}")]
    except (KeyError, TypeError):
        try:
            return mapping[f"/{key}"]
        except (KeyError, TypeError):
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
    trailer = re.search(rb"trailer\s<<(.?)>>", raw, re.S | re.I)
    if trailer is None:
        return None
    body = trailer.group(1)
    reference = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", body)
    if reference is not None:
        return _referenced_encrypt_dict(raw, int(reference.group(1)), int(reference.group(2)))
    if re.search(rb"/Encrypt\s*<<", body):
        return _parse_dict_body(_extract_inline_dict(body, b"/Encrypt"))
    return None


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
        output.append(byte)
    return bytes(output)


def _decode_pdf_literal_byte(payload: bytes, index: int) -> tuple[int, int]:
    """Decode one plain or backslash-escaped literal byte."""
    if payload[index] != 0x5C or index + 1 >= len(payload):
        return payload[index], index + 1
    escaped = payload[index + 1]
    named = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    if escaped in named:
        return named[escaped], index + 2
    if 0x30 <= escaped <= 0x37:
        return _decode_octal_escape(payload, index + 1)
    return escaped, index + 2


def _decode_octal_escape(payload: bytes, start: int) -> tuple[int, int]:
    """Decode a one-to-three digit octal escape starting at an octal byte."""
    end = start
    while end < len(payload) and end - start < 3 and 0x30 <= payload[end] <= 0x37:
        end += 1
    return int(payload[start:end], 8) & 0xFF, end


def _file_id_hex(raw: bytes) -> str | None:
    # /ID [<hex> <hex>]
    """Return PDF /ID hex pair for hashcat line construction."""
    m = re.search(rb"/ID\s\[\s<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", raw)
    if m:
        return m.group(1).decode("ascii").lower()
    m = re.search(rb"/ID\s\[\s\((.?)\)\s\((.*?)\)", raw, re.S)
    if m:
        g1 = m.group(1)
        return g1.hex() if isinstance(g1, bytes) else None
    # binary id strings
    m = re.search(rb"/ID\s\[(.?)\]", raw, re.S)
    if not m:
        return None
    body = m.group(1)
    hm = re.search(rb"<([0-9A-Fa-f]+)>", body)
    if hm:
        return hm.group(1).decode("ascii").lower()
    return None
