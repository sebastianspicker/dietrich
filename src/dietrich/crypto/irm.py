"""Detect IRM / Purview / RMS style server-bound protection.

Detection only - Dietrich will not fake a decrypt without a use license.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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
    header = path.read_bytes()[:8]
    details: list[str] = []

    # OLE / encrypted package path
    if header[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        try:
            import olefile

            if not olefile.isOleFile(str(path)):
                return IrmInfo(False, "none")
            with olefile.OleFileIO(str(path)) as ole:
                streams = {"/".join(s) for s in ole.listdir()}
                # DRM / IRM indicators
                # Standard Office open-password uses EncryptedPackage + EncryptionInfo
                # without DRM transform - not IRM.
                has_drm = any(
                    "drm" in s.lower() or "irm" in s.lower() or "rightsmanagement" in s.lower()
                    for s in streams
                )
                # DataSpaces Version / TransformInfo with DRM
                for s in streams:
                    low = s.lower()
                    if "transforminfo" in low and "drm" in low:
                        has_drm = True
                    if "drmencrypted" in low:
                        has_drm = True
                if has_drm:
                    details.append("OLE streams indicate DRM/IRM transform.")
                    details.append(
                        "Server-bound: needs Active Directory RMS / Azure IRM use license."
                    )
                    return IrmInfo(True, "ole_drm", tuple(details))
                # EUL / license streams
                if any(
                    s.split("/")[-1].lower() == "eul" or s.lower().endswith("/eul") for s in streams
                ):
                    details.append("End-user license stream present (IRM).")
                    return IrmInfo(True, "ole_drm", tuple(details))
        except Exception as exc:
            details.append(f"IRM probe limited: {exc}")

    # ZIP OOXML with feature rights or custom IRM XML
    if header[:2] == b"PK":
        try:
            import zipfile

            with zipfile.ZipFile(path) as zf:
                names = [n.lower() for n in zf.namelist()]
                for n in names:
                    if "irm" in n or "rightsmanagement" in n or "drm" in n:
                        details.append(f"Package part suggests IRM: {n}")
                        return IrmInfo(True, "ooxml_irm", tuple(details))
                # feature property bags
                for n in zf.namelist():
                    if n.endswith(".xml") and "customXml" in n:
                        try:
                            data = zf.read(n)[:4000].lower()
                        except Exception:
                            continue
                        if b"rightsmanagement" in data or b"msipc" in data:
                            details.append(f"customXml mentions rights management: {n}")
                            return IrmInfo(True, "ooxml_irm", tuple(details))
        except Exception as exc:
            details.append(f"ZIP IRM probe limited: {exc}")

    return IrmInfo(False, "none", tuple(details))


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
