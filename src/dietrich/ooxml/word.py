"""Word OOXML soft transformers: documentProtection and writeProtection."""

from __future__ import annotations

from dietrich.ooxml.xml_strip import count_elements, remove_elements_from_xml_bytes
from dietrich.types import PartStats, ProtectedPart, UnlockOptions

SETTINGS_PATH = "word/settings.xml"


def inspect_word_parts(names: list[str], read) -> list[ProtectedPart]:
    """Find documentProtection/writeProtection in settings."""
    parts: list[ProtectedPart] = []
    if SETTINGS_PATH not in names:
        return parts
    data = read(SETTINGS_PATH)
    for kind in ("documentProtection", "writeProtection"):
        count = count_elements(data, kind, SETTINGS_PATH)
        if count:
            parts.append(ProtectedPart(path=SETTINGS_PATH, kind=kind, count=count))
    return parts


def transform_word_part(
    name: str,
    data: bytes,
    options: UnlockOptions,
    stats: PartStats,
) -> bytes:
    """Remove Word soft protection elements from settings.xml."""
    if not options.remove_document_protection:
        return data
    if name.replace("\\", "/") != SETTINGS_PATH:
        return data
    data, removed = remove_elements_from_xml_bytes(data, "documentProtection", name)
    stats.add("documentProtection", removed)
    data, removed_w = remove_elements_from_xml_bytes(data, "writeProtection", name)
    stats.add("documentProtection", removed_w)  # counted under document protection family
    return data
