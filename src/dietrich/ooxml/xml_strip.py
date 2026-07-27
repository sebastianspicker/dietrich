"""Byte-preserving XML element removal using expat ranges.

Used so soft unlock deletes protection elements without rewriting unrelated
markup or namespace declarations.
"""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError, ParserCreate

from dietrich.errors import InvalidDocumentError


@dataclass(frozen=True)
class ElementFrame:
    """Expat stack frame: element local name and byte offsets while scanning."""

    local_name: str
    start: int
    start_tag_end: int
    target: bool


@dataclass(frozen=True)
class ElementRange:
    """Half-open byte range ``[start, end)`` of an element to delete."""

    start: int
    end: int


def local_name(tag: object) -> str:
    """Return the local name of a Clark or prefixed XML tag."""
    if not isinstance(tag, str):
        return ""
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[1]
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag.rsplit(":", 1)[-1]


def count_elements(source: bytes, element_local_name: str, path: str) -> int:
    """Count elements with the given local name in XML bytes."""
    try:
        root = ElementTree.fromstring(source)
    except ElementTree.ParseError as exc:
        raise InvalidDocumentError(f"{path} is not valid XML: {exc}") from exc
    return sum(1 for element in root.iter() if local_name(element.tag) == element_local_name)


def count_entry_elements(archive_read, name: str, element_local_name: str) -> int:
    """Count target elements in a ZIP entry via ``archive_read(name)``."""
    try:
        data = archive_read(name)
    except KeyError:
        return 0
    return count_elements(source=data, element_local_name=element_local_name, path=name)


def remove_elements_from_xml_bytes(
    source: bytes,
    element_local_name: str,
    path: str,
) -> tuple[bytes, int]:
    """Delete all elements with local name; preserve surrounding bytes."""
    ranges = find_element_ranges(source, element_local_name, path)
    if not ranges:
        return source, 0
    return remove_ranges(source, ranges), len(ranges)


def find_element_ranges(source: bytes, element_local_name: str, path: str) -> list[ElementRange]:
    """Return byte ranges of elements to remove."""
    parser = ParserCreate(namespace_separator="}")
    stack: list[ElementFrame] = []
    ranges: list[ElementRange] = []

    def start_element(name: str, attrs: dict[str, str]) -> None:
        """Expat StartElement handler: push frame with start offset."""
        del attrs
        start = parser.CurrentByteIndex
        frame_local_name = local_name(name)
        stack.append(
            ElementFrame(
                local_name=frame_local_name,
                start=start,
                start_tag_end=find_tag_end(source, start, path),
                target=frame_local_name == element_local_name,
            )
        )

    def end_element(name: str) -> None:
        """Expat EndElement handler: record range if this frame was a target."""
        del name
        frame = stack.pop()
        if not frame.target:
            return

        if parser.CurrentByteIndex == frame.start_tag_end:
            end = frame.start_tag_end
        else:
            end = find_tag_end(source, parser.CurrentByteIndex, path)
        ranges.append(ElementRange(start=frame.start, end=end))

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element

    try:
        parser.Parse(source, True)
    except ExpatError as exc:
        raise InvalidDocumentError(f"{path} is not valid XML: {exc}") from exc

    return ranges


def find_tag_end(source: bytes, start: int, path: str) -> int:
    """Find exclusive end offset of an XML start/end tag."""
    if start >= len(source) or source[start] != ord("<"):
        raise InvalidDocumentError(f"{path} has an invalid XML event offset.")

    quote: int | None = None
    index = start
    while index < len(source):
        byte = source[index]
        if quote is not None:
            if byte == quote:
                quote = None
        elif byte in {ord('"'), ord("'")}:
            quote = byte
        elif byte == ord(">"):
            return index + 1
        index += 1

    raise InvalidDocumentError(f"{path} has an unterminated XML tag.")


def remove_ranges(source: bytes, ranges: list[ElementRange]) -> bytes:
    """Splice out [start,end) ranges from source bytes."""
    cleaned_ranges = coalesce_ranges(ranges)
    output: list[bytes] = []
    cursor = 0
    for entry in cleaned_ranges:
        output.append(source[cursor : entry.start])
        cursor = entry.end
    output.append(source[cursor:])
    return b"".join(output)


def coalesce_ranges(ranges: list[ElementRange]) -> list[ElementRange]:
    """Merge overlapping/adjacent ElementRange values."""
    ordered = sorted(ranges, key=lambda entry: (entry.start, entry.end))
    coalesced: list[ElementRange] = []
    for entry in ordered:
        if not coalesced or entry.start > coalesced[-1].end:
            coalesced.append(entry)
            continue

        previous = coalesced[-1]
        coalesced[-1] = ElementRange(
            start=previous.start,
            end=max(previous.end, entry.end),
        )
    return coalesced
