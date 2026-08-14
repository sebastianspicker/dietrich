"""Package property soft flags (DocSecurity / MarkAsFinal)."""

from __future__ import annotations

import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from dietrich.ooxml.xml_strip import ElementLike, count_elements, local_name
from dietrich.types import PartStats, ProtectedPart, UnlockOptions

APP_PROPS = "docProps/app.xml"
CUSTOM_PROPS = "docProps/custom.xml"


def inspect_props_parts(names: list[str], read) -> list[ProtectedPart]:
    """Detect DocSecurity / MarkAsFinal package flags."""
    parts: list[ProtectedPart] = []
    if APP_PROPS in names:
        doc_security = _inspect_doc_security(read(APP_PROPS))
        if doc_security is not None:
            parts.append(doc_security)
    if CUSTOM_PROPS in names:
        data = read(CUSTOM_PROPS)
        if b"MarkAsFinal" in data or b"_MarkAsFinal" in data:
            parts.append(ProtectedPart(path=CUSTOM_PROPS, kind="MarkAsFinal", count=1))
    return parts


def _inspect_doc_security(data: bytes) -> ProtectedPart | None:
    """Report a non-zero DocSecurity value without accepting unsafe XML."""
    count = count_elements(data, "DocSecurity", APP_PROPS)
    if not count:
        return None
    try:
        root = ElementTree.fromstring(data)
        for element in root.iter():
            if local_name(element.tag) == "DocSecurity" and (element.text or "").strip() not in {
                "",
                "0",
            }:
                return ProtectedPart(path=APP_PROPS, kind="DocSecurity", count=1)
    except (DefusedXmlException, ElementTree.ParseError):
        return ProtectedPart(path=APP_PROPS, kind="DocSecurity", count=count)
    return None


def transform_props_part(
    name: str,
    data: bytes,
    options: UnlockOptions,
    stats: PartStats,
) -> bytes:
    """Clear DocSecurity/MarkAsFinal soft flags in package props."""
    if not options.remove_mark_as_final:
        return data
    normalized = name.replace("\\", "/")

    if normalized == APP_PROPS:
        return _clear_doc_security(data, stats)

    if normalized == CUSTOM_PROPS:
        return _clear_custom_mark_as_final(data, stats)

    return data


def _clear_doc_security(data: bytes, stats: PartStats) -> bytes:
    """Set a non-zero DocSecurity tag to zero while preserving its prefix shape."""
    pattern = rb"(<[^>]*DocSecurity[^>]*>)([^<]+)(</[^>]*DocSecurity>)"
    match = re.search(pattern, data, flags=re.I)
    if match is None or match.group(2).strip() in {b"", b"0"}:
        return data
    cleared = data[: match.start(2)] + b"0" + data[match.end(2) :]
    stats.add("markAsFinal", 1)
    return cleared


def _clear_custom_mark_as_final(data: bytes, stats: PartStats) -> bytes:
    """Remove custom-property MarkAsFinal flags, using a safe XML fallback."""
    if b"MarkAsFinal" not in data and b"_MarkAsFinal" not in data:
        return data
    try:
        return _remove_custom_properties(data, stats)
    except (DefusedXmlException, ElementTree.ParseError):
        return _remove_custom_properties_by_pattern(data, stats)


def _remove_custom_properties(data: bytes, stats: PartStats) -> bytes:
    """Remove matching custom-property elements from parsed XML."""
    root = ElementTree.fromstring(data)
    parent_map = {child: parent for parent in root.iter() for child in parent}
    removed = _remove_mark_as_final_elements(root, parent_map)
    if not removed:
        return data
    stats.add("markAsFinal", removed)
    body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=False)
    declaration_end = data.find(b"?>") if data.lstrip().startswith(b"<?xml") else -1
    return data[: declaration_end + 2] + b"\n" + body if declaration_end != -1 else body


def _remove_mark_as_final_elements(
    root: ElementLike,
    parent_map: dict[ElementLike, ElementLike],
) -> int:
    """Remove marked property elements and return the number actually detached."""
    removable = (element for element in root.iter() if _is_mark_as_final_property(element))
    return sum(_remove_element(parent_map.get(element), element) for element in removable)


def _remove_element(parent: ElementLike | None, element: ElementLike) -> int:
    """Detach an element when it has a parent in the parsed XML tree."""
    if parent is None:
        return 0
    parent.remove(element)
    return 1


def _is_mark_as_final_property(element: ElementLike) -> bool:
    """Return whether one custom-property element carries the MarkAsFinal flag."""
    if local_name(element.tag) != "property":
        return False
    return any(
        "MarkAsFinal" in value
        for key, value in element.attrib.items()
        if key == "name" or key.endswith("name")
    )


def _remove_custom_properties_by_pattern(data: bytes, stats: PartStats) -> bytes:
    """Remove malformed XML property blocks containing MarkAsFinal markers."""
    cleaned, removed = re.subn(
        rb"<[^>]*property[^>]*MarkAsFinal[^>]*/>|<property\b[^>]*MarkAsFinal.*?</property>",
        b"",
        data,
        flags=re.I | re.S,
    )
    if removed:
        stats.add("markAsFinal", removed)
    return cleaned if removed else data
