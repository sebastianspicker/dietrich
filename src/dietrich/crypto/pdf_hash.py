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

    r = _int_field(encrypt, "R")
    v = _int_field(encrypt, "V")
    p = _int_field(encrypt, "P")
    length = _int_field(encrypt, "Length")
    # Filter for Standard security handler only
    filter_name = _name_field(encrypt, "Filter") or "Standard"
    if filter_name not in {"Standard", "StandardCrypt"}:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported security handler /Filter {filter_name}"
        )

    o_hex = _string_field_hex(encrypt, "O")
    u_hex = _string_field_hex(encrypt, "U")
    if not o_hex or not u_hex:
        raise EncryptedDocumentError(f"{path.name}: missing /O or /U in Encrypt dict")

    id_hex = _file_id_hex(raw) or ("00" * 16)
    cfm = _name_field(encrypt, "CFM") or encrypt.get("CFM", "")
    bits = _pdf_key_bits(length=length, r=r, cfm=str(cfm))

    if r in {2, 3, 4}:
        # john/hashcat: $pdf$<V><R><bits><P><meta><id_len><id><u_len><u><o_len><o>
        meta = 0
        u_raw = bytes.fromhex(u_hex)
        o_raw = bytes.fromhex(o_hex)
        id_raw = bytes.fromhex(id_hex)
        u_use = u_raw[:32] if len(u_raw) >= 32 else u_raw
        o_use = o_raw[:32] if len(o_raw) >= 32 else o_raw
        hash_body = (
            f"$pdf${v or 2}*{r}*{bits}*{p if p is not None else 0}*{meta}*"
            f"{len(id_raw)}*{id_raw.hex()}*"
            f"{len(u_use)}*{u_use.hex()}*"
            f"{len(o_use)}*{o_use.hex()}"
        )
    elif r in {5, 6}:
        oe = _string_field_hex(encrypt, "OE")
        ue = _string_field_hex(encrypt, "UE")
        perms = _string_field_hex(encrypt, "Perms")
        if not (oe and ue and perms):
            raise EncryptedDocumentError(
                f"{path.name}: R={r} requires /OE /UE /Perms for hash export"
            )
        # hashcat 10700 / john pdf format for AES-256
        hash_body = (
            f"$pdf${v or 5}*{r}*256*{p if p is not None else 0}*1*"
            f"16*{id_hex[:32]}*"
            f"127*{u_hex[:254]}*"
            f"127*{o_hex[:254]}*"
            f"32*{ue[:64]}*"
            f"32*{oe[:64]}*"
            f"16*{perms[:32]}"
        )
    else:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported PDF revision R={r} for native hash export"
        )

    if fmt == "john":
        return f"{path.name}:{hash_body}"
    return hash_body


def _pdf_key_bits(*, length: int | None, r: int | None, cfm: str) -> int:
    """Derive key length in bits for PDF hash export.

    PDF /Length is often in bytes for crypt filters (16 → 128-bit AES).
    Legacy RC4 uses bit lengths 40/128 directly.
    """
    cfm_u = cfm.upper().replace("/", "")
    if "AESV3" in cfm_u or (r is not None and r >= 5):
        return 256
    if "AESV2" in cfm_u or "AES" in cfm_u:
        if length is None:
            return 128
        if length <= 32:  # bytes
            return length * 8
        return length  # already bits
    # RC4 / default
    if length is None:
        return 40 if (r is None or r <= 2) else 128
    if length <= 32:
        # Ambiguous: treat small values as bytes only for AES; RC4 uses 5..16 as bytes rarely
        if length in {5, 16}:
            return length * 8
        return length
    return length


def _encrypt_dict_via_pikepdf(path: Path) -> dict[str, str] | None:
    """Extract /Encrypt dict fields via pikepdf when possible."""
    try:
        import pikepdf
    except ImportError:
        return None
    try:
        # Open without password may fail; use empty password for owner-only
        try:
            pdf = pikepdf.open(path, password="")
        except pikepdf.PasswordError:
            # Still can read encryption params from trailer via open with allow
            return _encrypt_from_raw_trailer(path)
        try:
            if not pdf.is_encrypted:
                return None
            # pikepdf exposes encryption via _encryption / trailer
            enc = pdf.trailer.get("/Encrypt")
            if enc is None:
                return None
            enc = enc.get_object() if hasattr(enc, "get_object") else enc
            result: dict[str, str] = {}
            for key in ("R", "V", "P", "Length", "Filter"):
                if key in enc or f"/{key}" in [str(k) for k in enc.keys()]:
                    try:
                        val = enc[pikepdf.Name(f"/{key}")]
                    except Exception:
                        try:
                            val = enc[f"/{key}"]
                        except Exception:
                            continue
                    if key in {"R", "V", "P", "Length"}:
                        result[key] = str(int(val))
                    else:
                        result[key] = str(val).lstrip("/")
            for key in ("O", "U", "OE", "UE", "Perms"):
                try:
                    val = bytes(enc[pikepdf.Name(f"/{key}")])
                    result[key] = "<" + val.hex() + ">"
                except Exception:
                    continue
            # Nested crypt filter CFM (AESV2 / AESV3)
            try:
                cf = enc[pikepdf.Name("/CF")]
                cf = cf.get_object() if hasattr(cf, "get_object") else cf
                std = cf[pikepdf.Name("/StdCF")]
                std = std.get_object() if hasattr(std, "get_object") else std
                cfm = std[pikepdf.Name("/CFM")]
                result["CFM"] = str(cfm).lstrip("/")
                if "Length" not in result:
                    try:
                        result["Length"] = str(int(std[pikepdf.Name("/Length")]))
                    except Exception:
                        pass
            except Exception:
                pass
            return result if "O" in result and "U" in result else None
        finally:
            pdf.close()
    except Exception:
        return _encrypt_from_raw_trailer(path)


def _encrypt_from_raw_trailer(path: Path) -> dict[str, str] | None:
    """Fallback: parse /Encrypt from raw PDF trailer bytes."""
    return _find_encrypt_dict(path.read_bytes())


def _find_encrypt_dict(raw: bytes) -> dict[str, str] | None:
    """Very small PDF tokenizer: find /Encrypt dict body as key→value strings."""
    # Prefer trailer reference: /Encrypt N M R
    trailer_m = re.search(rb"trailer\s<<(.?)>>", raw, re.S | re.I)
    encrypt_ref = None
    if trailer_m:
        tbody = trailer_m.group(1)
        ref_m = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", tbody)
        if ref_m:
            encrypt_ref = (int(ref_m.group(1)), int(ref_m.group(2)))
        elif re.search(rb"/Encrypt\s*<<", tbody):
            # inline encrypt
            return _parse_dict_body(_extract_inline_dict(tbody, b"/Encrypt"))

    if encrypt_ref:
        obj_m = re.search(
            rf"{encrypt_ref[0]}\s+{encrypt_ref[1]}\s+obj".encode(),
            raw,
        )
        if obj_m:
            body = _extract_balanced_dict(raw, obj_m.end())
            if body is not None:
                parsed = _parse_dict_body(body)
                if "O" in parsed and "U" in parsed:
                    return parsed

    # Fallback: scan for dicts that look like Standard security handler
    for m in re.finditer(rb"<<", raw):
        body = _extract_balanced_dict(raw, m.start())
        if body is None:
            continue
        if b"/Filter" in body and b"/Standard" in body and b"/O" in body and b"/U" in body:
            return _parse_dict_body(body)
    return None


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
    v = d.get(key)
    if v is None:
        return None
    if v.startswith("<") and v.endswith(">"):
        return v[1:-1].lower()
    if v.startswith("(") and v.endswith(")"):
        # PDF literal string → bytes → hex
        out = bytearray()
        raw = v.encode("latin-1")
        # extract between first ( and last )
        try:
            start = raw.index(b"(") + 1
            end = raw.rindex(b")")
            payload = raw[start:end]
        except ValueError:
            return None
        i = 0
        while i < len(payload):
            if payload[i] == 0x5C and i + 1 < len(payload):  # backslash
                nxt = payload[i + 1]
                escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
                if nxt in escapes:
                    out.append(escapes[nxt])
                    i += 2
                elif 0x30 <= nxt <= 0x37:  # octal
                    j = i + 1
                    octal = b""
                    while j < len(payload) and len(octal) < 3 and 0x30 <= payload[j] <= 0x37:
                        octal += bytes([payload[j]])
                        j += 1
                    out.append(int(octal, 8) & 0xFF)
                    i = j
                else:
                    out.append(nxt)
                    i += 2
            else:
                out.append(payload[i])
                i += 1
        return bytes(out).hex()
    return None


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
