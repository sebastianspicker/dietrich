"""CFBF/OLE classification and inspect metadata for legacy binary Office."""

from __future__ import annotations

from pathlib import Path

from dietrich.errors import MissingDependencyError, UnsupportedFormatError
from dietrich.types import DocumentFormat, DocumentInspection

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def is_cfbf(path: Path) -> bool:
    """True if file starts with OLE/CFB magic."""
    with path.open("rb") as handle:
        return handle.read(8) == CFBF_MAGIC


def inspect_cfbf(path: Path) -> DocumentInspection:
    """Inspect CFBF streams and return DocumentInspection."""
    input_path = Path(path)
    notes: list[str] = [
        "Legacy CFBF binary Office: soft structure-protection rewrite is supported.",
        "If open-password encrypted, use --password / --wordlist / --hashcat (msoffcrypto).",
    ]
    kind = "unknown"
    streams: list[str] = []
    try:
        import olefile
    except ImportError as exc:
        raise MissingDependencyError(
            "Legacy CFBF inspect requires: pip install 'dietrich[research]' (olefile)."
        ) from exc

    if not olefile.isOleFile(str(input_path)):
        raise UnsupportedFormatError(f"{input_path} is not a valid CFBF/OLE file.")

    with olefile.OleFileIO(str(input_path)) as ole:
        streams = ["/".join(s) for s in ole.listdir()]
        if "Workbook" in streams or any(s.endswith("/Workbook") for s in streams):
            kind = "xls"
        elif "WordDocument" in streams:
            kind = "doc"
        elif "PowerPoint Document" in streams:
            kind = "ppt"
        if "EncryptionInfo" in streams or "EncryptedPackage" in streams:
            kind = "encrypted_ooxml"

    if kind == "encrypted_ooxml":
        strategies = (
            "crypto:ooxml_password",
            "crypto:wordlist",
            "crypto:export_hash",
        )
        return DocumentInspection(
            input_path=input_path,
            document_format=DocumentFormat.ENCRYPTED_OOXML,
            strategies=strategies,
            encrypted=True,
            user_password_required=True,
            notes=tuple(notes + [f"streams={len(streams)}", f"kind={kind}"]),
        )

    return DocumentInspection(
        input_path=input_path,
        document_format=DocumentFormat.LEGACY_CFBF,
        strategies=("soft:binary_protection", f"legacy:{kind}"),
        encrypted=False,
        notes=tuple(notes + [f"streams={len(streams)}", f"kind={kind}"]),
    )
