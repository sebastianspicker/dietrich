"""Route hash export to Office or PDF exporters by document class."""

from __future__ import annotations

from pathlib import Path

from dietrich.crypto import ooxml_crypto, pdf_crypto
from dietrich.errors import EncryptedDocumentError
from dietrich.types import DocumentFormat


def export_hash(path: Path, document_format: DocumentFormat, fmt: str = "hashcat") -> str:
    """Dispatch hash export by DocumentFormat to Office or PDF exporters."""
    path = Path(path)
    if document_format == DocumentFormat.PDF:
        return pdf_crypto.export_hash_line(path, fmt)

    if document_format in {
        DocumentFormat.ENCRYPTED_OOXML,
        DocumentFormat.LEGACY_CFBF,
        DocumentFormat.EXCEL_OOXML,
        DocumentFormat.WORD_OOXML,
        DocumentFormat.POWERPOINT_OOXML,
        DocumentFormat.UNKNOWN,
    }:
        # Encrypted Office is OLE; attempt real export or raise.
        try:
            return ooxml_crypto.export_hash_line(path, fmt)
        except EncryptedDocumentError:
            raise
        except Exception as exc:
            raise EncryptedDocumentError(
                f"could not export Office hash for {path.name}: {exc}"
            ) from exc

    raise EncryptedDocumentError(f"hash export not supported for format {document_format.value}")
