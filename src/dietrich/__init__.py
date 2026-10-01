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
from dietrich.domain.assessment import (
    Blocker,
    BlockerCode,
    Capability,
    CapabilityCode,
)
from dietrich.domain.models import (
    AttackOptions,
    AttackResult,
    DocumentFormat,
    DocumentInspection,
    ProtectedPart,
    ProtectedWorksheet,
    ProtectionLayer,
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
    OperationCancelledError,
    OutputExistsError,
    PasswordNotFoundError,
    SignedDocumentError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from dietrich.operation import OperationControl

__all__ = [
    "OperationControl",
    "OperationCancelledError",
    "AttackOptions",
    "AttackResult",
    "Blocker",
    "BlockerCode",
    "Capability",
    "CapabilityCode",
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
    "ProtectionLayer",
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
