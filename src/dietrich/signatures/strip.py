"""Remove OOXML digital signature parts and related content types/relationships."""

from __future__ import annotations

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from dietrich.ooxml.xml_strip import local_name
from dietrich.safety.zip_archive import is_signed_package_member

CONTENT_TYPES = "[Content_Types].xml"
RELS_CANDIDATES = (
    "_rels/.rels",
    "xl/_rels/workbook.xml.rels",
    "word/_rels/document.xml.rels",
    "ppt/_rels/presentation.xml.rels",
)

_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def strip_signature_members(
    names: list[str],
    read,
) -> tuple[set[str], dict[str, bytes]]:
    """Return (members_to_skip, rewritten_parts).

    Removes `_xmlsignatures/*` and signature relationship/content-type entries.
    Does not forge signatures.
    """
    skip = _signed_members(names)

    rewritten: dict[str, bytes] = {}
    if not skip:
        return skip, rewritten

    if CONTENT_TYPES in names:
        rewritten[CONTENT_TYPES] = _strip_content_types(read(CONTENT_TYPES), skip)

    rewritten.update(_signature_relationship_parts(names, read, rewritten))

    return skip, rewritten


def _signed_members(names: list[str]) -> set[str]:
    """Normalize package members that must be removed with a signature."""
    return {name.replace("\\", "/") for name in names if is_signed_package_member(name)}


def _signature_relationship_parts(
    names: list[str], read, rewritten: dict[str, bytes]
) -> dict[str, bytes]:
    """Rewrite standard and discovered relationship parts that reference signatures."""
    rewritten_parts: dict[str, bytes] = {}
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized in rewritten or not normalized.endswith(".rels"):
            continue
        data = read(name)
        if normalized in RELS_CANDIDATES or _mentions_signature(data):
            rewritten_parts[normalized] = _strip_relationships(data)
    return rewritten_parts


def _mentions_signature(data: bytes) -> bool:
    """Detect a relationship payload that needs signature-target removal."""
    lowered = data.lower()
    return b"_xmlsignatures" in lowered or b"digitalsignature" in lowered


def _strip_content_types(source: bytes, skip: set[str]) -> bytes:
    """Internal helper: _strip_content_types."""
    try:
        root = ElementTree.fromstring(source)
    except (DefusedXmlException, ElementTree.ParseError):
        return source

    for child in _content_type_removals(root, skip):
        root.remove(child)
    return _serialize_like_source(root, source)


def _content_type_removals(root, skip: set[str]) -> list[ElementTree.Element]:
    """Collect content-type entries associated with removed signature members."""
    return [child for child in list(root) if _is_signature_content_type(child, skip)]


def _is_signature_content_type(child, skip: set[str]) -> bool:
    """Return whether one Default or Override entry belongs to a signature part."""
    if local_name(child.tag) not in {"Override", "Default"}:
        return False
    part = _attribute_ending_in(child.attrib, "PartName")
    content_type = _attribute_ending_in(child.attrib, "ContentType")
    normalized = (part or "").lstrip("/").replace("\\", "/").lower()
    if "xmlsignatures" in normalized or "digitalsignature" in (content_type or "").lower():
        return True
    return any(
        signature.lower().rstrip("/") in normalized or normalized in signature.lower()
        for signature in skip
    )


def _attribute_ending_in(attributes: dict[str, str], name: str) -> str | None:
    """Read a namespaced or unprefixed XML attribute by local-name suffix."""
    for key, value in attributes.items():
        if key == name or key.endswith(name):
            return value
    return None


def _strip_relationships(source: bytes) -> bytes:
    """Internal helper: _strip_relationships."""
    try:
        root = ElementTree.fromstring(source)
    except (DefusedXmlException, ElementTree.ParseError):
        return source

    for child in list(root):
        if _is_signature_relationship(child):
            root.remove(child)

    return _serialize_like_source(root, source)


def _is_signature_relationship(child) -> bool:
    """Return whether a relationship target or type references a signature."""
    if local_name(child.tag) != "Relationship":
        return False
    target = (_attribute_ending_in(child.attrib, "Target") or "").lower()
    rel_type = (_attribute_ending_in(child.attrib, "Type") or "").lower()
    return "_xmlsignatures" in target or "digitalsignature" in target or any(
        marker in rel_type for marker in ("digitalsignature", "digital-signature")
    )


def _serialize_like_source(root, source: bytes) -> bytes:
    """Serialize XML while preserving a source XML declaration when present."""
    body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=False)
    if source.lstrip().startswith(b"<?xml"):
        decl_end = source.find(b"?>")
        if decl_end != -1:
            return source[: decl_end + 2] + b"\n" + body
    return body
