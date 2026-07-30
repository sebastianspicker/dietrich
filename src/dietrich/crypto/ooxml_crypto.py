"""Office open-password verify/decrypt and hash export via msoffcrypto.

Handles Agile/Standard encryption: password verify (no full decrypt per try),
decrypt-to-path, and office2john-compatible ``$office$*`` hash lines.
"""

from __future__ import annotations

import binascii
import io
from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, MissingDependencyError


@dataclass(frozen=True)
class OfficeEncryptionInfo:
    """Classified open-encryption metadata for inspect + hash export."""

    scheme: str  # agile | standard | binary | unknown
    version_label: str  # e.g. "2013", "2010", "2007"
    hash_algorithm: str | None
    cipher_bits: int | None
    spin_count: int | None
    salt_size: int | None
    cost_class: str  # trivial | moderate | expensive
    hashcat_mode: int | None
    notes: tuple[str, ...] = ()


def _require_msoffcrypto():
    """Import msoffcrypto or raise MissingDependencyError."""
    try:
        import msoffcrypto
    except ImportError as exc:
        raise MissingDependencyError(
            "OOXML encryption handling requires the crypto extra: "
            "pip install 'dietrich[crypto]' (msoffcrypto-tool)."
        ) from exc
    return msoffcrypto


def is_encrypted_office_file(path: Path) -> bool:
    """True if msoffcrypto reports the file as encrypted."""
    msoffcrypto = _require_msoffcrypto()
    with path.open("rb") as handle:
        try:
            office = msoffcrypto.OfficeFile(handle)
        except (
            AttributeError,
            msoffcrypto.exceptions.FileFormatError,
            msoffcrypto.exceptions.ParseError,
            OSError,
            TypeError,
            ValueError,
        ):
            return False
        return bool(getattr(office, "is_encrypted", lambda: False)())


def open_office(path: Path):
    """Open an OfficeFile handle (caller must close_office)."""
    msoffcrypto = _require_msoffcrypto()
    handle = path.open("rb")
    try:
        office = msoffcrypto.OfficeFile(handle)
    except (
        AttributeError,
        msoffcrypto.exceptions.FileFormatError,
        msoffcrypto.exceptions.ParseError,
        OSError,
        TypeError,
        ValueError,
    ):
        handle.close()
        raise
    # Keep handle alive on the office object for subsequent ops.
    office._dietrich_handle = handle
    return office


def close_office(office) -> None:
    """Close the file handle attached by open_office."""
    handle = getattr(office, "_dietrich_handle", None)
    if handle is not None:
        handle.close()


def describe_encryption(path: Path) -> OfficeEncryptionInfo:
    """Return scheme/cost metadata for an encrypted Office file."""
    office = open_office(path)
    try:
        if not office.is_encrypted():
            return _unencrypted_info()

        otype = getattr(office, "type", None) or "unknown"
        info = getattr(office, "info", None) or {}
        if otype == "agile":
            return _agile_encryption_info(info)
        if otype == "standard":
            return _standard_encryption_info()
        return _unknown_encryption_info(otype)
    finally:
        close_office(office)


def _unencrypted_info() -> OfficeEncryptionInfo:
    """Describe a recognized Office container without open-password encryption."""
    return OfficeEncryptionInfo(
        scheme="none",
        version_label="none",
        hash_algorithm=None,
        cipher_bits=None,
        spin_count=None,
        salt_size=None,
        cost_class="none",
        hashcat_mode=None,
        notes=("File is not open-password encrypted.",),
    )


def _agile_encryption_info(info: dict) -> OfficeEncryptionInfo:
    """Describe Agile encryption fields and map supported hashcat modes."""
    algorithm, bits, spin, salt = _agile_fields(info)
    version, mode = _agile_version_and_mode(algorithm)
    notes = _agile_notes(algorithm, spin)
    return OfficeEncryptionInfo(
        scheme="agile",
        version_label=version,
        hash_algorithm=algorithm or None,
        cipher_bits=bits,
        spin_count=spin,
        salt_size=_agile_salt_size(salt),
        cost_class=_agile_cost_class(spin),
        hashcat_mode=mode,
        notes=tuple(notes),
    )


def _agile_fields(info: dict) -> tuple[str, int | None, int | None, bytes]:
    """Normalize optional Agile EncryptionInfo fields into stable value types."""
    algorithm = str(info.get("passwordHashAlgorithm") or "")
    bits = int(info.get("passwordKeyBits") or 0) or None
    spin = int(info.get("spinValue") or 0) or None
    return algorithm, bits, spin, info.get("passwordSalt") or b""


def _agile_salt_size(salt: bytes) -> int | None:
    """Return a reported salt size only when EncryptionInfo supplied a salt."""
    return len(salt) if salt else None


def _agile_cost_class(spin: int | None) -> str:
    """Classify Agile work factor for caller-facing recovery guidance."""
    return "expensive" if (spin or 0) >= 100_000 else "moderate"


def _agile_version_and_mode(algorithm: str) -> tuple[str, int | None]:
    """Map known Agile hash algorithms to Office versions and hashcat modes."""
    if algorithm.upper() == "SHA512":
        return "2013", 9600
    if algorithm.upper() == "SHA1":
        return "2010", 9500
    return "agile", None


def _agile_notes(algorithm: str, spin: int | None) -> list[str]:
    """Produce user-facing notes for Agile capability and cost."""
    notes: list[str] = []
    if _agile_version_and_mode(algorithm)[1] is None:
        notes.append(f"Unsupported hash algorithm for hash export: {algorithm}")
    if spin:
        notes.append(
            f"AES Agile encryption; spinCount={spin}. "
            "CPU dictionary is slow - prefer GPU (hashcat) after --export-hash."
        )
    return notes


def _standard_encryption_info() -> OfficeEncryptionInfo:
    """Describe ECMA-376 Standard encryption."""
    return OfficeEncryptionInfo(
        scheme="standard",
        version_label="2007",
        hash_algorithm=None,
        cipher_bits=None,
        spin_count=None,
        salt_size=16,
        cost_class="moderate",
        hashcat_mode=9400,
        notes=("Standard ECMA-376 encryption (Office 2007-class).",),
    )


def _unknown_encryption_info(otype: object) -> OfficeEncryptionInfo:
    """Describe encrypted Office types without a dedicated implementation."""
    scheme = str(otype)
    notes = [f"Encrypted Office scheme type={otype!r}."]
    cost = "moderate"
    if otype in {"rc4", "rc4cryptoapi", "xor"}:
        cost = "trivial"
        notes.append("Legacy weak scheme - local brute/dictionary often sufficient.")
    return OfficeEncryptionInfo(
        scheme=scheme,
        version_label=scheme,
        hash_algorithm=None,
        cipher_bits=None,
        spin_count=None,
        salt_size=None,
        cost_class=cost,
        hashcat_mode=None,
        notes=tuple(notes),
    )


def try_password(path: Path, password: str) -> bool:
    """Return True if password verifies (fast path; no full decrypt)."""
    msoffcrypto = _require_msoffcrypto()
    office = open_office(path)
    try:
        if not office.is_encrypted():
            return True
        try:
            _load_office_key(office, password, verify_only=True)
            return True
        except (OSError, RuntimeError, ValueError):
            return False
        except msoffcrypto.exceptions.DecryptionError:
            return False
    finally:
        close_office(office)


def decrypt_to(path: Path, password: str, output_path: Path) -> None:
    """Decrypt encrypted Office file to output_path with the given password."""
    msoffcrypto = _require_msoffcrypto()
    office = open_office(path)
    try:
        if not office.is_encrypted():
            output_path.write_bytes(path.read_bytes())
            return
        try:
            _load_office_key(office, password, verify_only=False)
        except msoffcrypto.exceptions.InvalidKeyError as exc:
            raise EncryptedDocumentError("incorrect password for encrypted Office file") from exc
        except msoffcrypto.exceptions.DecryptionError as exc:
            raise EncryptedDocumentError(f"could not load encryption key: {exc}") from exc
        except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
            raise EncryptedDocumentError(f"could not load encryption key: {exc}") from exc
        with output_path.open("wb") as out:
            try:
                office.decrypt(out)
            except (ValueError, OSError, RuntimeError) as exc:
                raise EncryptedDocumentError(f"decrypt failed: {exc}") from exc
    finally:
        close_office(office)


def _load_office_key(office, password: str, *, verify_only: bool) -> None:
    """Use modern verification when available and decrypt to a sink on older releases."""
    try:
        office.load_key(password=password, verify_password=True)
    except TypeError:
        office.load_key(password=password)
        if verify_only:
            office.decrypt(io.BytesIO())


def export_hash_line(path: Path, fmt: str = "hashcat") -> str:
    """Export a real office2john / hashcat-compatible Office hash line.

    Format (Agile):
      [name:]$office${2010|2013}{spin}{keyBits}{saltSize}{salt}{encVerifier}*{encVerifierHash32}

    hashcat modes: 9600 (2013/SHA512), 9500 (2010/SHA1), 9400 (2007).
    """
    path = Path(path)
    office = open_office(path)
    try:
        if not office.is_encrypted():
            raise EncryptedDocumentError(f"{path.name} is not open-password encrypted")

        hash_body = _office_hash_body(office, path)
        return f"{path.name}:{hash_body}" if fmt == "john" else hash_body
    finally:
        close_office(office)


def _office_hash_body(office, path: Path) -> str:
    """Build a native Agile hash or delegate Standard and legacy types to OLE parsing."""
    otype = getattr(office, "type", None)
    if otype == "agile":
        return _agile_hash_body(getattr(office, "info", None) or {})
    try:
        return _export_standard_hash_from_ole(path)
    except EncryptedDocumentError:
        if otype == "standard":
            raise
        raise EncryptedDocumentError(
            f"hash export not supported for scheme type={otype!r}; "
            "use John the Ripper office2john.py for this file."
        ) from None


def _agile_hash_body(info: dict) -> str:
    """Format an Agile EncryptionInfo mapping as an office2john-compatible hash."""
    algorithm = str(info.get("passwordHashAlgorithm") or "")
    version = _agile_hash_version(algorithm)
    spin = int(info["spinValue"])
    key_bits = int(info["passwordKeyBits"])
    salt = bytes(info["passwordSalt"])
    encrypted_verifier = bytes(info["encryptedVerifierHashInput"])
    encrypted_hash = bytes(info["encryptedVerifierHashValue"])
    return (
        f"$office${version}{spin}{key_bits}{len(salt)}*"
        f"{binascii.hexlify(salt).decode('ascii')}*"
        f"{binascii.hexlify(encrypted_verifier).decode('ascii')}*"
        f"{binascii.hexlify(encrypted_hash[:32]).decode('ascii')}"
    )


def _agile_hash_version(algorithm: str) -> int:
    """Map supported Agile password hashes to Office hashcat family versions."""
    if algorithm.upper() == "SHA512":
        return 2013
    if algorithm.upper() == "SHA1":
        return 2010
    raise EncryptedDocumentError(f"unsupported Agile hash algorithm for export: {algorithm}")


def _export_standard_hash_from_ole(path: Path) -> str:
    """Parse ECMA-376 Standard / Office 2007 EncryptionInfo (office2john layout)."""
    import struct

    import olefile

    path = Path(path)
    if not olefile.isOleFile(str(path)):
        raise EncryptedDocumentError(
            f"{path.name}: not an OLE compound file; cannot export standard hash"
        )

    with olefile.OleFileIO(str(path)) as ole:
        if not ole.exists("EncryptionInfo"):
            raise EncryptedDocumentError(f"{path.name}: no EncryptionInfo stream")
        stream = ole.openstream("EncryptionInfo")
        major = struct.unpack("<H", stream.read(2))[0]
        minor = struct.unpack("<H", stream.read(2))[0]
        flags = struct.unpack("<I", stream.read(4))[0]
        del flags
        # Agile is major=4,minor=4 - should not reach here for agile
        if major == 4 and minor == 4:
            raise EncryptedDocumentError(
                f"{path.name}: EncryptionInfo looks Agile; use Agile export path"
            )
        header_length = struct.unpack("<I", stream.read(4))[0]
        # skipFlags
        stream.read(4)
        header_length -= 4
        stream.read(4)  # sizeExtra
        header_length -= 4
        stream.read(4)  # algId
        header_length -= 4
        stream.read(4)  # algHashId
        header_length -= 4
        key_size = struct.unpack("<I", stream.read(4))[0]
        header_length -= 4
        stream.read(4)  # providerType
        header_length -= 4
        stream.read(4)  # unused
        header_length -= 4
        stream.read(4)  # unused
        header_length -= 4
        if header_length > 0:
            stream.read(header_length)  # CSPName
        salt_size = struct.unpack("<I", stream.read(4))[0]
        salt = stream.read(salt_size)
        encrypted_verifier = stream.read(16)
        verifier_hash_size = struct.unpack("<I", stream.read(4))[0]
        encrypted_verifier_hash = stream.read(verifier_hash_size)

    return (
        f"$office$2007{verifier_hash_size}{key_size}{salt_size}*"
        f"{binascii.hexlify(salt).decode('ascii')}*"
        f"{binascii.hexlify(encrypted_verifier).decode('ascii')}*"
        f"{binascii.hexlify(encrypted_verifier_hash)[:64].decode('ascii')}"
    )
