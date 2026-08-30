"""Bounded document-container validation helpers."""

from dietrich.safety.cfb import CFBF_MAGIC, validate_cfb
from dietrich.safety.zip_archive import (
    MAX_ARCHIVE_MEMBERS,
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_UNCOMPRESSED_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    SIGNED_PACKAGE_PREFIX,
    is_signed_package_member,
    package_is_signed,
    validate_archive_safety,
)

__all__ = [
    "MAX_ARCHIVE_MEMBERS",
    "MAX_COMPRESSION_RATIO",
    "MAX_MEMBER_UNCOMPRESSED_BYTES",
    "MAX_TOTAL_UNCOMPRESSED_BYTES",
    "SIGNED_PACKAGE_PREFIX",
    "CFBF_MAGIC",
    "is_signed_package_member",
    "package_is_signed",
    "validate_cfb",
    "validate_archive_safety",
]
