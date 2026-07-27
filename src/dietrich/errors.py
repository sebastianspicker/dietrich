"""User-facing exception hierarchy for Dietrich.

All recoverable product errors subclass :class:`DietrichError` so the CLI can
map them to exit codes without catching bare ``Exception``.
"""

from __future__ import annotations


class DietrichError(Exception):
    """Base class for user-facing document errors."""


class UnsupportedFormatError(DietrichError):
    """Raised when the input path/format is not supported for the requested operation."""


class InvalidDocumentError(DietrichError):
    """Raised when the document cannot be parsed."""


class EncryptedDocumentError(DietrichError):
    """Raised when encryption is detected and cannot be handled as requested."""


class UnsafeArchiveError(InvalidDocumentError):
    """Raised when an archive exceeds safe processing limits."""


class SignedDocumentError(DietrichError):
    """Raised when a digitally signed package would be invalidated by rewrite."""


class OutputExistsError(DietrichError):
    """Raised when the output path exists and overwrite is disabled."""


class PasswordNotFoundError(DietrichError):
    """Raised when password recovery exhausts candidates without success."""


class MissingDependencyError(DietrichError):
    """Raised when an optional extra is required but not installed."""
