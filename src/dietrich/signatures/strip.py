"""Remove OOXML digital signature parts and related content types/relationships."""

from __future__ import annotations

from xml.etree import ElementTree

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
    skip: set[str] = set()
    for name in names:
        if is_signed_package_member(name):
            skip.add(name.replace("\\", "/"))

    rewritten: dict[str, bytes] = {}
    if not skip:
        return skip, rewritten

    if CONTENT_TYPES in names:
        rewritten[CONTENT_TYPES] = _strip_content_types(read(CONTENT_TYPES), skip)

    for rels in RELS_CANDIDATES:
        if rels not in names:
            continue
        rewritten[rels] = _strip_relationships(read(rels))

    # Also rewrite any other .rels that mention xmlsignatures
    for name in names:
        norm = name.replace("\\", "/")
        if norm in rewritten or not norm.endswith(".rels"):
            continue
        data = read(name)
        if b"_xmlsignatures" in data.lower() or b"digitalsignature" in data.lower():
            rewritten[norm] = _strip_relationships(data)

    return skip, rewritten


def _strip_content_types(source: bytes, skip: set[str]) -> bytes:
    """Internal helper: _strip_content_types."""
    try:
        root = ElementTree.fromstring(source)
    except ElementTree.ParseError:
        return source

    # Collect children to remove
    to_remove: list[ElementTree.Element] = []
    for child in list(root):
        tag = local_name(child.tag)
        if tag not in {"Override", "Default"}:
            continue
        part = child.attrib.get("PartName") or child.attrib.get(f"{{{_CT_NS}}}PartName")
        content_type = child.attrib.get("ContentType") or child.attrib.get(
            f"{{{_CT_NS}}}ContentType"
        )
        # Unprefixed attrs after parse without namespace map
        if part is None:
            part = child.attrib.get("PartName")
        for key, val in child.attrib.items():
            if key.endswith("PartName"):
                part = val
            if key.endswith("ContentType"):
                content_type = val
        part_norm = (part or "").lstrip("/").replace("\\", "/").lower()
        ct = (content_type or "").lower()
        if "xmlsignatures" in part_norm or "digitalsignature" in ct:
            to_remove.append(child)
            continue
        for sig in skip:
            if sig.lower().rstrip("/") in part_norm or part_norm in sig.lower():
                to_remove.append(child)
                break
    for child in to_remove:
        root.remove(child)

    body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=False)
    if source.lstrip().startswith(b"<?xml"):
        decl_end = source.find(b"?>")
        if decl_end != -1:
            return source[: decl_end + 2] + b"\n" + body
    return body


def _strip_relationships(source: bytes) -> bytes:
    """Internal helper: _strip_relationships."""
    try:
        root = ElementTree.fromstring(source)
    except ElementTree.ParseError:
        return source

    to_remove: list[ElementTree.Element] = []
    for child in list(root):
        if local_name(child.tag) != "Relationship":
            continue
        target = ""
        rel_type = ""
        for key, val in child.attrib.items():
            if key == "Target" or key.endswith("}Target") or key.endswith("Target"):
                target = val
            if key == "Type" or key.endswith("}Type") or key.endswith("Type"):
                rel_type = val
        t_low = target.lower()
        ty_low = rel_type.lower()
        if (
            "_xmlsignatures" in t_low
            or "digitalsignature" in t_low
            or "digitalsignature" in ty_low
            or "digital-signature" in ty_low
        ):
            to_remove.append(child)
    for child in to_remove:
        root.remove(child)

    body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=False)
    if source.lstrip().startswith(b"<?xml"):
        decl_end = source.find(b"?>")
        if decl_end != -1:
            return source[: decl_end + 2] + b"\n" + body
    return body
