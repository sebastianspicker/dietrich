"""Office open-password verify/decrypt and hash export via msoffcrypto.

Handles Agile/Standard encryption: password verify (no full decrypt per try),
decrypt-to-path, and office2john-compatible ``$office$*`` hash lines.
"""

from __future__ import annotations

import binascii
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
        except Exception:
            return False
        return bool(getattr(office, "is_encrypted", lambda: False)())


def open_office(path: Path):
    """Open an OfficeFile handle (caller must close_office)."""
    msoffcrypto = _require_msoffcrypto()
    handle = path.open("rb")
    try:
        office = msoffcrypto.OfficeFile(handle)
    except Exception:
        handle.close()
        raise
    # Keep handle alive on the office object for subsequent ops.
    office._dietrich_handle = handle  # noqa: SLF001
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

        otype = getattr(office, "type", None) or "unknown"
        info = getattr(office, "info", None) or {}
        notes: list[str] = []

        if otype == "agile":
            algo = str(info.get("passwordHashAlgorithm") or "")
            bits = int(info.get("passwordKeyBits") or 0) or None
            spin = int(info.get("spinValue") or 0) or None
            salt = info.get("passwordSalt") or b""
            if algo.upper() == "SHA512":
                version = "2013"
                mode = 9600
            elif algo.upper() == "SHA1":
                version = "2010"
                mode = 9500
            else:
                version = "agile"
                mode = None
                notes.append(f"Unsupported hash algorithm for hash export: {algo}")
            cost = "expensive" if (spin or 0) >= 100_000 else "moderate"
            if spin:
                notes.append(
                    f"AES Agile encryption; spinCount={spin}. "
                    "CPU dictionary is slow - prefer GPU (hashcat) after --export-hash."
                )
            return OfficeEncryptionInfo(
                scheme="agile",
                version_label=version,
                hash_algorithm=algo or None,
                cipher_bits=bits,
                spin_count=spin,
                salt_size=len(salt) if salt else None,
                cost_class=cost,
                hashcat_mode=mode,
                notes=tuple(notes),
            )

        if otype == "standard":
            # ECMA-376 Standard / Office 2007-style
            notes.append("Standard ECMA-376 encryption (Office 2007-class).")
            return OfficeEncryptionInfo(
                scheme="standard",
                version_label="2007",
                hash_algorithm=None,
                cipher_bits=None,
                spin_count=None,
                salt_size=16,
                cost_class="moderate",
                hashcat_mode=9400,
                notes=tuple(notes),
            )

        notes.append(f"Encrypted Office scheme type={otype!r}.")
        cost = "moderate"
        if otype in {"rc4", "rc4cryptoapi", "xor"}:
            cost = "trivial"
            notes.append("Legacy weak scheme - local brute/dictionary often sufficient.")
        return OfficeEncryptionInfo(
            scheme=str(otype),
            version_label=str(otype),
            hash_algorithm=None,
            cipher_bits=None,
            spin_count=None,
            salt_size=None,
            cost_class=cost,
            hashcat_mode=None,
            notes=tuple(notes),
        )
    finally:
        close_office(office)


def try_password(path: Path, password: str) -> bool:
    """Return True if password verifies (fast path; no full decrypt)."""
    office = open_office(path)
    try:
        if not office.is_encrypted():
            return True
        try:
            office.load_key(password=password, verify_password=True)
            return True
        except TypeError:
            # Older msoffcrypto without verify_password
            try:
                office.load_key(password=password)
                import io

                sink = io.BytesIO()
                office.decrypt(sink)
                return True
            except (ValueError, OSError, RuntimeError):
                return False
        except (ValueError, OSError, RuntimeError):
            return False
        except Exception as exc:
            # msoffcrypto raises InvalidKeyError (subclass of Exception)
            name = type(exc).__name__
            if "Key" in name or "Password" in name or "Invalid" in name:
                return False
            raise
    finally:
        close_office(office)


def decrypt_to(path: Path, password: str, output_path: Path) -> None:
    """Decrypt encrypted Office file to output_path with the given password."""
    office = open_office(path)
    try:
        if not office.is_encrypted():
            output_path.write_bytes(path.read_bytes())
            return
        try:
            try:
                office.load_key(password=password, verify_password=True)
            except TypeError:
                office.load_key(password=password)
        except Exception as exc:
            name = type(exc).__name__
            if "Key" in name or "Password" in name or "Invalid" in name:
                raise EncryptedDocumentError(
                    "incorrect password for encrypted Office file"
                ) from exc
            raise EncryptedDocumentError(f"could not load encryption key: {exc}") from exc
        with output_path.open("wb") as out:
            try:
                office.decrypt(out)
            except (ValueError, OSError, RuntimeError) as exc:
                raise EncryptedDocumentError(f"decrypt failed: {exc}") from exc
    finally:
        close_office(office)


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

        otype = getattr(office, "type", None)
        info = getattr(office, "info", None) or {}

        if otype == "agile":
            algo = str(info.get("passwordHashAlgorithm") or "")
            if algo.upper() == "SHA512":
                version = 2013
            elif algo.upper() == "SHA1":
                version = 2010
            else:
                raise EncryptedDocumentError(f"unsupported Agile hash algorithm for export: {algo}")
            spin = int(info["spinValue"])
            key_bits = int(info["passwordKeyBits"])
            salt = bytes(info["passwordSalt"])
            enc_ver = bytes(info["encryptedVerifierHashInput"])
            enc_hash = bytes(info["encryptedVerifierHashValue"])
            salt_size = len(salt)
            # office2john uses first 32 bytes of encryptedVerifierHash (64 hex chars).
            hash_body = (
                f"$office${version}{spin}{key_bits}{salt_size}*"
                f"{binascii.hexlify(salt).decode('ascii')}*"
                f"{binascii.hexlify(enc_ver).decode('ascii')}*"
                f"{binascii.hexlify(enc_hash[:32]).decode('ascii')}"
            )
        elif otype == "standard":
            hash_body = _export_standard_hash_from_ole(path)
        else:
            # Try standard OLE parse before giving up (some types still use EncryptionInfo).
            try:
                hash_body = _export_standard_hash_from_ole(path)
            except EncryptedDocumentError:
                raise EncryptedDocumentError(
                    f"hash export not supported for scheme type={otype!r}; "
                    "use John the Ripper office2john.py for this file."
                ) from None

        if fmt == "john":
            return f"{path.name}:{hash_body}"
        # hashcat: no filename prefix
        return hash_body
    finally:
        close_office(office)


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
