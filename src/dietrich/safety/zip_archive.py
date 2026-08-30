"""Reject hostile or unsafe OOXML ZIP metadata before member reads."""

from __future__ import annotations

import zipfile
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import unquote

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
    _reject_duplicate_names(names)

    if not allow_signed and package_is_signed(names):
        raise SignedDocumentError(
            "digitally signed OOXML packages are unsupported because rewriting invalidates "
            "signatures. Pass strip_signatures=True / --strip-signatures for an unsigned copy."
        )

    total_size = 0
    for info in entries:
        _validate_member_limits(info)
        total_size += info.file_size
        if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise UnsafeArchiveError(
                f"archive expands to more than {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes."
            )


def _reject_duplicate_names(names: list[str]) -> None:
    """Reject unsafe or duplicate names after OPC URI normalization."""
    canonical = [_canonical_member_name(name) for name in names]
    if len(canonical) != len(set(canonical)):
        raise UnsafeArchiveError("archive contains duplicate or aliased member names.")


def _canonical_member_name(name: str) -> str:
    """Return a comparison form for one safe package-relative OPC part name."""
    if not name or "\\" in name or "?" in name or "#" in name:
        raise UnsafeArchiveError(f"archive member has an unsafe package name: {name!r}")
    decoded = unquote(name)
    if decoded.startswith("/") or "\\" in decoded or PureWindowsPath(decoded).drive:
        raise UnsafeArchiveError(f"archive member has an unsafe package name: {name!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in decoded):
        raise UnsafeArchiveError(f"archive member has control characters: {name!r}")
    normalized = decoded.rstrip("/")
    if not normalized:
        raise UnsafeArchiveError(f"archive member has an unsafe package name: {name!r}")
    parts = PurePosixPath(normalized).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafeArchiveError(f"archive member has path traversal: {name!r}")
    return "/".join(parts)


def _validate_member_limits(info: zipfile.ZipInfo) -> None:
    """Validate one member's expansion and compression limits."""
    if info.file_size > MAX_MEMBER_UNCOMPRESSED_BYTES:
        raise UnsafeArchiveError(
            f"{info.filename} expands to {info.file_size} bytes; the per-member limit is "
            f"{MAX_MEMBER_UNCOMPRESSED_BYTES}."
        )
    if compression_ratio_exceeds_limit(info):
        raise UnsafeArchiveError(
            f"{info.filename} exceeds the compression ratio limit of {MAX_COMPRESSION_RATIO}:1."
        )
