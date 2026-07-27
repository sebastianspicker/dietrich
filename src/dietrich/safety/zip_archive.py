"""Reject hostile or unsafe OOXML ZIP metadata before member reads."""

from __future__ import annotations

import zipfile

from dietrich.errors import EncryptedDocumentError, SignedDocumentError, UnsafeArchiveError

MAX_ARCHIVE_MEMBERS = 10_000
MAX_MEMBER_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
SIGNED_PACKAGE_PREFIX = "_xmlsignatures/"


def is_signed_package_member(name: str) -> bool:
    """Identify the OOXML digital-signature part namespace without reading member data."""
    return name.replace("\\", "/").lower().startswith(SIGNED_PACKAGE_PREFIX)


def package_is_signed(names: list[str] | tuple[str, ...]) -> bool:
    """True if any member is a digital-signature part."""
    return any(is_signed_package_member(name) for name in names)


def reject_encrypted_entries(archive: zipfile.ZipFile) -> None:
    """Raise if ZIP entries use traditional ZIP encryption flags."""
    encrypted_names = tuple(
        info.filename for info in archive.infolist() if info.flag_bits & (0x01 | 0x40)
    )
    if encrypted_names:
        sample = ", ".join(encrypted_names[:3])
        suffix = "" if len(encrypted_names) <= 3 else ", ..."
        raise EncryptedDocumentError(f"encrypted ZIP entries are unsupported: {sample}{suffix}")


def compression_ratio_exceeds_limit(info: zipfile.ZipInfo) -> bool:
    """Return whether ZIP metadata describes a potentially explosive member."""
    if info.file_size == 0:
        return False
    if info.compress_size == 0:
        return True
    return info.file_size > info.compress_size * MAX_COMPRESSION_RATIO


def validate_archive_safety(
    archive: zipfile.ZipFile,
    *,
    allow_signed: bool = False,
) -> None:
    """Reject archives whose metadata is unsafe to process before reading members."""
    entries = archive.infolist()
    if len(entries) > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError(
            f"archive has {len(entries)} entries; the limit is {MAX_ARCHIVE_MEMBERS}."
        )

    reject_encrypted_entries(archive)
    names = [info.filename for info in entries]
    if len(names) != len(set(names)):
        raise UnsafeArchiveError("archive contains duplicate member names.")

    if not allow_signed and package_is_signed(names):
        raise SignedDocumentError(
            "digitally signed OOXML packages are unsupported because rewriting invalidates "
            "signatures. Pass strip_signatures=True / --strip-signatures for an unsigned copy."
        )

    total_size = 0
    for info in entries:
        if info.file_size > MAX_MEMBER_UNCOMPRESSED_BYTES:
            raise UnsafeArchiveError(
                f"{info.filename} expands to {info.file_size} bytes; the per-member limit is "
                f"{MAX_MEMBER_UNCOMPRESSED_BYTES}."
            )
        if compression_ratio_exceeds_limit(info):
            raise UnsafeArchiveError(
                f"{info.filename} exceeds the compression ratio limit of {MAX_COMPRESSION_RATIO}:1."
            )
        total_size += info.file_size
        if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise UnsafeArchiveError(
                f"archive expands to more than {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes."
            )
