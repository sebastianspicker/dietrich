"""Shared synthetic OOXML builders."""

from __future__ import annotations

import zipfile
from pathlib import Path


def write_ooxml(
    path: Path,
    parts: dict[str, bytes],
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    """Write a minimal OOXML ZIP with Content_Types/_rels defaults plus parts."""
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        if "[Content_Types].xml" not in parts:
            archive.writestr("[Content_Types].xml", b"<Types/>")
        if "_rels/.rels" not in parts:
            archive.writestr("_rels/.rels", b"<Relationships/>")
        for name, data in parts.items():
            archive.writestr(name, data)
    return path


def protected_xlsx(path: Path) -> Path:
    """Synthetic xlsx with sheetProtection + workbookProtection for soft-unlock tests."""
    return write_ooxml(
        path,
        {
            "xl/workbook.xml": (
                b'<?xml version="1.0"?>'
                b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
                b' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                b'<workbookProtection lockStructure="1"/>'
                b'<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
                b"</workbook>"
            ),
            "xl/worksheets/sheet1.xml": (
                b'<?xml version="1.0"?>'
                b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<sheetProtection sheet="1"/>'
                b"<sheetData>"
                b'<row r="1"><c r="A1" t="inlineStr"><is><t>keep-me</t></is></c></row>'
                b"</sheetData></worksheet>"
            ),
            "xl/_rels/workbook.xml.rels": (
                b"<Relationships "
                b'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
                b'officeDocument/2006/relationships/worksheet" '
                b'Target="worksheets/sheet1.xml"/>'
                b"</Relationships>"
            ),
        },
    )


def protected_docx(path: Path) -> Path:
    """Synthetic docx with documentProtection for soft-unlock tests."""
    return write_ooxml(
        path,
        {
            "word/document.xml": (
                b'<?xml version="1.0"?>'
                b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b"<w:body><w:p><w:r><w:t>keep-me</w:t></w:r></w:p></w:body></w:document>"
            ),
            "word/settings.xml": (
                b'<?xml version="1.0"?>'
                b'<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:documentProtection w:edit="readOnly" w:enforcement="1"/>'
                b"</w:settings>"
            ),
        },
    )


def protected_pptx(path: Path) -> Path:
    """Synthetic pptx with modifyVerifier for soft-unlock tests."""
    return write_ooxml(
        path,
        {
            "ppt/presentation.xml": (
                b'<?xml version="1.0"?>'
                b'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                b'<p:modifyVerifier p:algorithmName="SHA-512" p:hashValue="abc"/>'
                b"<p:sldIdLst/>"
                b"</p:presentation>"
            ),
        },
    )
