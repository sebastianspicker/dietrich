"""Excel OOXML soft transformers: sheet/chartsheet and workbook protection."""

from __future__ import annotations

from dietrich.ooxml.xml_strip import count_elements, remove_elements_from_xml_bytes
from dietrich.types import PartStats, ProtectedPart, UnlockOptions

WORKSHEET_PREFIXES = (
    "xl/worksheets/",
    "xl/chartsheets/",
    "xl/dialogsheets/",
    "xl/macrosheets/",
)
WORKBOOK_PATH = "xl/workbook.xml"
VBA_PROJECT_PATHS = frozenset({"xl/vbaProject.bin", "word/vbaProject.bin", "ppt/vbaProject.bin"})


def is_sheet_xml(name: str) -> bool:
    """True for worksheet/chartsheet/dialogsheet/macrosheet parts."""
    normalized = name.replace("\\", "/")
    if not normalized.endswith(".xml"):
        return False
    return any(normalized.startswith(prefix) for prefix in WORKSHEET_PREFIXES)


# Back-compat alias
is_worksheet_xml = is_sheet_xml


def inspect_excel_parts(names: list[str], read) -> list[ProtectedPart]:
    """Find sheetProtection/workbookProtection parts."""
    parts: list[ProtectedPart] = []
    for name in names:
        if is_sheet_xml(name):
            data = read(name)
            count = count_elements(data, "sheetProtection", name)
            if count:
                parts.append(ProtectedPart(path=name, kind="sheetProtection", count=count))
    if WORKBOOK_PATH in names:
        data = read(WORKBOOK_PATH)
        count = count_elements(data, "workbookProtection", WORKBOOK_PATH)
        if count:
            parts.append(ProtectedPart(path=WORKBOOK_PATH, kind="workbookProtection", count=count))
    return parts


def transform_excel_part(
    name: str,
    data: bytes,
    options: UnlockOptions,
    stats: PartStats,
) -> bytes:
    """Remove Excel soft protection elements from one ZIP part."""
    if options.remove_worksheet_protection and is_sheet_xml(name):
        data, removed = remove_elements_from_xml_bytes(data, "sheetProtection", name)
        stats.add("sheetProtection", removed)
    elif options.remove_workbook_protection and name.replace("\\", "/") == WORKBOOK_PATH:
        data, removed = remove_elements_from_xml_bytes(data, "workbookProtection", name)
        stats.add("workbookProtection", removed)
    return data
