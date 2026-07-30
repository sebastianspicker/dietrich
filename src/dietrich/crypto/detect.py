"""Magic-byte and structure-based document classification.

Decides OOXML vs PDF vs CFBF vs encrypted OLE so dispatch can pick the soft
or hard unlock path.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from dietrich.errors import EncryptedDocumentError, InvalidDocumentError, MissingDependencyError
from dietrich.types import DocumentFormat, DocumentInspection

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"


def classify_path(path: Path) -> DocumentInspection:
    """Classify a document by magic bytes and light structure inspection."""
    input_path = Path(path)
    if not input_path.is_file():
        raise InvalidDocumentError(f"{input_path} is not a file.")

    header = input_path.read_bytes()[:8]

    if header.startswith(PDF_MAGIC):
        return _classify_pdf(input_path)
    if header.startswith(CFBF_MAGIC):
        return _classify_cfbf(input_path)
    if header.startswith(ZIP_MAGIC) or header[:2] == b"PK":
        return _classify_zip_ooxml(input_path)

    # Some encrypted Office files are CFBF with EncryptionInfo.
    suffix = input_path.suffix.lower()
    if suffix == ".pdf":
        return _classify_pdf(input_path)
    if suffix in {".xls", ".doc", ".ppt"}:
        # Magic was not CFBF; still offer product soft path if file is readable OLE later,
        # otherwise honest guidance (no dead --legacy-binary flag).
        return DocumentInspection(
            input_path=input_path,
            document_format=DocumentFormat.LEGACY_CFBF,
            strategies=("soft:binary_protection",),
            notes=(
                "Suffix indicates binary Office (.xls/.doc/.ppt). "
                "If the file is valid OLE/CFBF, soft structure-protection rewrite is available; "
                "if open-password encrypted, use --password / --wordlist / --hashcat.",
            ),
        )

    return DocumentInspection(
        input_path=input_path,
        document_format=DocumentFormat.UNKNOWN,
        strategies=(),
        notes=("Unrecognized file magic; cannot classify.",),
    )


def _classify_pdf(path: Path) -> DocumentInspection:
    """Build DocumentInspection for a PDF path."""
    from dietrich.pdf.inspect import inspect_pdf

    return inspect_pdf(path)


def _classify_cfbf(path: Path) -> DocumentInspection:
    # Encrypted OOXML is often a CFBF container with EncryptionInfo + EncryptedPackage.
    """Build DocumentInspection for OLE/CFBF (encrypted or legacy)."""
    fmt, encrypted, strategies, notes = _cfbf_container_summary(path)
    metadata = _cfbf_encryption_metadata(path, encrypted, notes, strategies)
    return DocumentInspection(
        input_path=path,
        document_format=fmt,
        strategies=tuple(dict.fromkeys(strategies)),
        encrypted=encrypted,
        user_password_required=encrypted,
        notes=tuple(notes),
        encryption_scheme=metadata[0],
        encryption_version=metadata[1],
        encryption_spin_count=metadata[2],
        encryption_cost_class=metadata[3],
        hashcat_mode=metadata[4],
    )


def _cfbf_container_summary(path: Path) -> tuple[DocumentFormat, bool, list[str], list[str]]:
    """Classify OLE streams when possible, then retain the bounded byte heuristic."""
    try:
        import olefile  # type: ignore
    except ImportError:
        olefile = None
    strategies: list[str] = []
    notes: list[str] = []
    if olefile is not None and olefile.isOleFile(str(path)):
        with olefile.OleFileIO(str(path)) as ole:
            streams = {"/".join(s) for s in ole.listdir()}
        return _cfbf_stream_summary(streams, strategies, notes)
    return _cfbf_heuristic_summary(path, strategies, notes)


def _cfbf_stream_summary(streams: set[str], strategies: list[str], notes: list[str]):
    """Summarize known OLE streams while retaining mask support from rich inspection."""
    if "EncryptionInfo" in streams or "EncryptedPackage" in streams:
        strategies.extend(
            ("crypto:ooxml_password", "crypto:wordlist", "crypto:mask", "crypto:export_hash")
        )
        return DocumentFormat.ENCRYPTED_OOXML, True, strategies, notes
    strategies.append("soft:binary_protection")
    notes.append("CFBF/OLE binary Office: soft structure-protection rewrite available.")
    return DocumentFormat.LEGACY_CFBF, False, strategies, notes


def _cfbf_heuristic_summary(path: Path, strategies: list[str], notes: list[str]):
    """Use the original bounded byte heuristic when olefile is unavailable."""
    blob = path.read_bytes()[:65536]
    if b"EncryptionInfo" in blob or b"EncryptedPackage" in blob:
        strategies.extend(("crypto:ooxml_password", "crypto:wordlist", "crypto:export_hash"))
        return DocumentFormat.ENCRYPTED_OOXML, True, strategies, notes
    strategies.append("soft:binary_protection")
    notes.append("CFBF detected. Install dietrich[research] (olefile) for richer stream inspect.")
    return DocumentFormat.LEGACY_CFBF, False, strategies, notes


def _cfbf_encryption_metadata(path: Path, encrypted: bool, notes: list[str], strategies: list[str]):
    """Add best-effort encryption metadata without changing classification on failure."""
    if not encrypted:
        return None, None, None, None, None
    try:
        from dietrich.crypto.ooxml_crypto import describe_encryption

        meta = describe_encryption(path)
        notes.extend(meta.notes)
        if meta.hashcat_mode:
            strategies.append(f"crypto:hashcat_mode_{meta.hashcat_mode}")
        return meta.scheme, meta.version_label, meta.spin_count, meta.cost_class, meta.hashcat_mode
    except (
        AttributeError,
        EncryptedDocumentError,
        KeyError,
        MissingDependencyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        notes.append(f"Encryption metadata limited: {exc}")
        return None, None, None, None, None


def _classify_zip_ooxml(path: Path) -> DocumentInspection:
    """Build DocumentInspection for an OOXML ZIP package."""
    from dietrich.ooxml.package import inspect_ooxml_package

    try:
        return inspect_ooxml_package(path, allow_signed=True)
    except zipfile.BadZipFile:
        # Might still be encrypted or corrupt
        return DocumentInspection(
            input_path=path,
            document_format=DocumentFormat.UNKNOWN,
            strategies=(),
            notes=("ZIP magic present but archive is unreadable.",),
        )


def detect_encrypted_ooxml(path: Path) -> bool:
    """True if path looks like encrypted OOXML-in-OLE."""
    header = path.read_bytes()[:8]
    if header.startswith(CFBF_MAGIC):
        inspection = _classify_cfbf(path)
        return inspection.document_format == DocumentFormat.ENCRYPTED_OOXML
    return False
