"""PowerPoint OOXML soft transformers: modifyVerifier removal."""

from __future__ import annotations

from dietrich.ooxml.xml_strip import count_elements, remove_elements_from_xml_bytes
from dietrich.types import PartStats, ProtectedPart, UnlockOptions

PRESENTATION_PATH = "ppt/presentation.xml"


def inspect_powerpoint_parts(names: list[str], read) -> list[ProtectedPart]:
    """Find modifyVerifier in presentation.xml."""
    parts: list[ProtectedPart] = []
    if PRESENTATION_PATH in names:
        data = read(PRESENTATION_PATH)
        count = count_elements(data, "modifyVerifier", PRESENTATION_PATH)
        if count:
            parts.append(ProtectedPart(path=PRESENTATION_PATH, kind="modifyVerifier", count=count))
    return parts


def transform_powerpoint_part(
    name: str,
    data: bytes,
    options: UnlockOptions,
    stats: PartStats,
) -> bytes:
    """Remove PowerPoint modifyVerifier from one part."""
    if options.remove_modify_verifier and name.replace("\\", "/") == PRESENTATION_PATH:
        data, removed = remove_elements_from_xml_bytes(data, "modifyVerifier", name)
        stats.add("modifyVerifier", removed)
    return data
