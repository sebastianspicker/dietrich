"""Package property soft flags (DocSecurity / MarkAsFinal)."""

from __future__ import annotations

import re
from xml.etree import ElementTree

from dietrich.ooxml.xml_strip import count_elements, local_name
from dietrich.types import PartStats, ProtectedPart, UnlockOptions

APP_PROPS = "docProps/app.xml"
CUSTOM_PROPS = "docProps/custom.xml"


def inspect_props_parts(names: list[str], read) -> list[ProtectedPart]:
    """Detect DocSecurity / MarkAsFinal package flags."""
    parts: list[ProtectedPart] = []
    if APP_PROPS in names:
        data = read(APP_PROPS)
        count = count_elements(data, "DocSecurity", APP_PROPS)
        if count:
            # Only report if non-zero
            try:
                root = ElementTree.fromstring(data)
                for el in root.iter():
                    if local_name(el.tag) == "DocSecurity" and (el.text or "").strip() not in {
                        "",
                        "0",
                    }:
                        parts.append(ProtectedPart(path=APP_PROPS, kind="DocSecurity", count=1))
                        break
            except ElementTree.ParseError:
                parts.append(ProtectedPart(path=APP_PROPS, kind="DocSecurity", count=count))
    if CUSTOM_PROPS in names:
        data = read(CUSTOM_PROPS)
        if b"MarkAsFinal" in data or b"_MarkAsFinal" in data:
            parts.append(ProtectedPart(path=CUSTOM_PROPS, kind="MarkAsFinal", count=1))
    return parts


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
        # Prefer in-place text replace to preserve namespaces/prefixes.
        import re

        def _zero_docsec(match: re.Match[bytes]) -> bytes:
            """Internal helper: _zero_docsec."""
            return match.group(1) + b"0" + match.group(3)

        new_data, n = re.subn(
            rb"(<[^>]*DocSecurity[^>]*>)([^<]+)(</[^>]*DocSecurity>)",
            _zero_docsec,
            data,
            count=1,
            flags=re.I,
        )
        if n and new_data != data:
            # Only count if original text was non-zero
            m = re.search(
                rb"<[^>]*DocSecurity[^>]*>([^<]+)</[^>]*DocSecurity>",
                data,
                flags=re.I,
            )
            if m and m.group(1).strip() not in {b"", b"0"}:
                stats.add("markAsFinal", 1)
                return new_data
        return data

    if normalized == CUSTOM_PROPS:
        # Remove property elements whose name attribute is MarkAsFinal / _MarkAsFinal.
        if b"MarkAsFinal" not in data and b"_MarkAsFinal" not in data:
            return data
        try:
            root = ElementTree.fromstring(data)
        except ElementTree.ParseError:
            # Fallback: remove property blocks containing MarkAsFinal
            cleaned, n = re.subn(
                rb"<[^>]*property[^>]*MarkAsFinal[^>]*/>|<property\b[^>]*MarkAsFinal.*?</property>",
                b"",
                data,
                flags=re.I | re.S,
            )
            if n:
                stats.add("markAsFinal", n)
            return cleaned if n else data

        removed = 0
        parent_map = {c: p for p in root.iter() for c in p}
        to_remove: list[ElementTree.Element] = []
        for el in root.iter():
            if local_name(el.tag) != "property":
                continue
            prop_name = el.attrib.get("name") or el.attrib.get(
                "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}name"
            )
            # Attributes may be unprefixed name=
            if prop_name is None:
                for key, val in el.attrib.items():
                    if key.endswith("name") or key == "name":
                        prop_name = val
                        break
            if prop_name and "MarkAsFinal" in prop_name:
                to_remove.append(el)
        for el in to_remove:
            parent = parent_map.get(el)
            if parent is not None:
                parent.remove(el)
                removed += 1
        if removed:
            stats.add("markAsFinal", removed)
            body = ElementTree.tostring(root, encoding="utf-8", xml_declaration=False)
            if data.lstrip().startswith(b"<?xml"):
                decl_end = data.find(b"?>")
                if decl_end != -1:
                    return data[: decl_end + 2] + b"\n" + body
            return body
        return data

    return data
