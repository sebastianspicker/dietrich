"""Detect IRM / Purview / RMS style server-bound protection.

Detection only - Dietrich will not fake a decrypt without a use license.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

from dietrich.errors import DietrichError
from dietrich.safety.bounded_io import read_file_prefix, read_zip_member_prefix
from dietrich.safety.zip_archive import validate_archive_safety


@dataclass(frozen=True)
class IrmInfo:
    """Detected IRM/Purview/RMS markers (detect-only; no local decrypt)."""

    is_irm: bool
    kind: str  # none | ooxml_irm | ole_drm | pdf_unknown
    details: tuple[str, ...] = ()


def detect_irm(path: Path) -> IrmInfo:
    """Detect IRM/RMS-style protection that requires a license server.

    Dietrich does not decrypt IRM without a valid use-license; this is
    detection and user guidance only.
    """
    path = Path(path)
    header = read_file_prefix(path, 8)
    details: list[str] = []

    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        result = _probe_ole_irm(path, details)
        if result is not None:
            return result

    if header[:2] == b"PK":
        result = _probe_zip_irm(path, details)
        if result is not None:
            return result

    return IrmInfo(False, "none", tuple(details))


def _probe_ole_irm(path: Path, details: list[str]) -> IrmInfo | None:
    """Probe OLE streams while retaining best-effort IRM diagnostics."""
    try:
        import olefile

        if not olefile.isOleFile(str(path)):
            return None
        with olefile.OleFileIO(str(path)) as ole:
            streams = {"/".join(stream) for stream in ole.listdir()}
    except (AttributeError, ImportError, OSError, TypeError, ValueError) as exc:
        details.append(f"IRM probe limited: {exc}")
        return None
    if _has_ole_drm_marker(streams):
        details.extend(
            (
                "OLE streams indicate DRM/IRM transform.",
                "Server-bound: needs Active Directory RMS / Azure IRM use license.",
            )
        )
        return IrmInfo(True, "ole_drm", tuple(details))
    if any(_is_eul_stream(stream) for stream in streams):
        details.append("End-user license stream present (IRM).")
        return IrmInfo(True, "ole_drm", tuple(details))
    return None


def _has_ole_drm_marker(streams: set[str]) -> bool:
    """Recognize DRM transform and rights-management OLE stream names."""
    for stream in streams:
        name = stream.lower()
        if any(marker in name for marker in ("drm", "irm", "rightsmanagement")):
            return True
        if "transforminfo" in name and "drm" in name:
            return True
        if "drmencrypted" in name:
            return True
    return False


def _is_eul_stream(stream: str) -> bool:
    """Return whether an OLE stream is an end-user license marker."""
    name = stream.lower()
    return name.split("/")[-1] == "eul" or name.endswith("/eul")


def _probe_zip_irm(path: Path, details: list[str]) -> IrmInfo | None:
    """Probe OOXML package names and custom XML for rights markers."""
    try:
        with zipfile.ZipFile(path) as archive:
            validate_archive_safety(archive, allow_signed=True)
            names = archive.namelist()
            part = next((name for name in names if _has_irm_marker(name)), None)
            if part is not None:
                details.append(f"Package part suggests IRM: {part.lower()}")
                return IrmInfo(True, "ooxml_irm", tuple(details))
            part = _custom_xml_rights_part(archive, names)
    except (
        DietrichError,
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        details.append(f"ZIP IRM probe limited: {exc}")
        return None
    if part is not None:
        details.append(f"customXml mentions rights management: {part}")
        return IrmInfo(True, "ooxml_irm", tuple(details))
    return None


def _has_irm_marker(part_name: str) -> bool:
    """Check a package member name for recognized rights-management markers."""
    name = part_name.lower()
    return any(marker in name for marker in ("irm", "rightsmanagement", "drm"))


def _custom_xml_rights_part(archive, names: list[str]) -> str | None:
    """Find custom XML that explicitly references rights-management metadata."""
    for name in names:
        if not (name.endswith(".xml") and "customXml" in name):
            continue
        try:
            data = read_zip_member_prefix(archive, name, 4_000).lower()
        except (
            KeyError,
            NotImplementedError,
            OSError,
            RuntimeError,
            ValueError,
            zipfile.BadZipFile,
        ):
            continue
        if b"rightsmanagement" in data or b"msipc" in data:
            return name
    return None


def irm_block_message(info: IrmInfo) -> str:
    """User-facing explanation when IRM blocks unlock."""
    return (
        "This file appears protected by IRM / Microsoft Purview / Azure RMS "
        f"({info.kind}). Dietrich cannot remove server-bound rights management "
        "without a valid use license from the issuing tenant. "
        "Open the file in Office while signed in to the authorized account, "
        "or ask the document owner to remove IRM. "
        + (" ".join(info.details) if info.details else "")
    )
