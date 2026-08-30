"""Dietrich - the office picklock.

In German, Dietrich means both picklock and a classic men's first name.
This package unlocks Office/PDF soft protection (and recovers open passwords)
for documents you own - like old man Dietrich in the office with a picklock.
"""

from dietrich.dispatch import (
    export_document_hash,
    inspect_document,
    inspect_workbook,
    unlock_document,
    unlock_workbook,
)
from dietrich.domain.models import (
    AttackOptions,
    AttackResult,
    DocumentFormat,
    DocumentInspection,
    ProtectedPart,
    ProtectedWorksheet,
    RemovalCounts,
    UnlockOptions,
    UnlockResult,
    WorkbookInspection,
)
from dietrich.errors import (
    DietrichError,
    EncryptedDocumentError,
    InvalidDocumentError,
    MissingDependencyError,
    OutputExistsError,
    PasswordNotFoundError,
    SignedDocumentError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)

__all__ = [
    "AttackOptions",
    "AttackResult",
    "DietrichError",
    "DocumentFormat",
    "DocumentInspection",
    "EncryptedDocumentError",
    "InvalidDocumentError",
    "MissingDependencyError",
    "OutputExistsError",
    "PasswordNotFoundError",
    "ProtectedPart",
    "ProtectedWorksheet",
    "RemovalCounts",
    "SignedDocumentError",
    "UnlockOptions",
    "UnlockResult",
    "UnsafeArchiveError",
    "UnsupportedFormatError",
    "WorkbookInspection",
    "export_document_hash",
    "inspect_document",
    "inspect_workbook",
    "unlock_document",
    "unlock_workbook",
]

__version__ = "0.4.0a5"
