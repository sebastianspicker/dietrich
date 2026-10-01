"""Native PDF ``/Encrypt`` hash export for hashcat/john (no pdf2john required).

Parses Standard security handler fields and derives key bits from Length/CFM.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, InvalidDocumentError
from dietrich.operation import checkpoint
from dietrich.pdf.trailer import (
    file_id_hex,
    find_encrypt_dict,
    int_field,
    name_field,
    string_field_hex,
)
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
    checkpoint("exporting PDF hash")
    try:
        raw = read_file_limited(path, MAX_NATIVE_PDF_HASH_BYTES)
    except ValueError as exc:
        raise InvalidDocumentError(
            f"{path.name} exceeds the native PDF hash parser limit of "
            f"{MAX_NATIVE_PDF_HASH_BYTES} bytes"
        ) from exc
    if not raw.startswith(b"%PDF"):
        raise InvalidDocumentError(f"{path.name} is not a PDF")
    checkpoint()

    # Prefer pikepdf encryption params when available (handles modern writers).
    encrypt = _encrypt_dict_via_pikepdf(path, raw) or find_encrypt_dict(raw)
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
    r = int_field(encrypt, "R")
    v = int_field(encrypt, "V")
    p = int_field(encrypt, "P")
    length = int_field(encrypt, "Length")
    filter_name = name_field(encrypt, "Filter") or "Standard"
    if filter_name not in {"Standard", "StandardCrypt"}:
        raise EncryptedDocumentError(
            f"{path.name}: unsupported security handler /Filter {filter_name}"
        )
    o_hex = string_field_hex(encrypt, "O")
    u_hex = string_field_hex(encrypt, "U")
    if not o_hex or not u_hex:
        raise EncryptedDocumentError(f"{path.name}: missing /O or /U in Encrypt dict")
    cfm = name_field(encrypt, "CFM") or encrypt.get("CFM", "")
    bits = _pdf_key_bits(length=length, r=r, cfm=str(cfm))
    return r, _PdfHashFields(
        version=v,
        permissions=p,
        key_bits=bits,
        owner_hex=o_hex,
        user_hex=u_hex,
        file_id_hex=file_id_hex(raw) or ("00" * 16),
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
    oe = string_field_hex(encrypt, "OE")
    ue = string_field_hex(encrypt, "UE")
    perms = string_field_hex(encrypt, "Perms")
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


def _encrypt_dict_via_pikepdf(path: Path, raw: bytes) -> dict[str, str] | None:
    """Extract /Encrypt dict fields via pikepdf when possible."""
    try:
        import pikepdf
    except ImportError:
        return None
    return _pikepdf_encrypt_or_raw(path, pikepdf, raw)


def _pikepdf_encrypt_or_raw(path: Path, pikepdf, raw: bytes) -> dict[str, str] | None:
    """Use pikepdf when it can open the file, otherwise retain raw-trailer fallback."""
    checkpoint()
    try:
        pdf = pikepdf.open(path)
    except (pikepdf.PasswordError, pikepdf.PdfError, OSError, TypeError, ValueError):
        return find_encrypt_dict(raw)
    try:
        return _opened_pikepdf_encrypt_dict(pdf, pikepdf)
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return find_encrypt_dict(raw)
    finally:
        pdf.close()
        checkpoint()


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
