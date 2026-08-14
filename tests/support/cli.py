"""Shared helpers for process-level CLI tests and documentation captures.

All product demos should go through ``python -m dietrich`` (or alias modules)
so exit codes and stdout match what users see.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from tests.support.ooxml import write_ooxml

ROOT = Path(__file__).resolve().parents[2]


def run_dietrich(
    *args: str,
    check: bool = False,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m dietrich`` with args; never raise unless check=True."""
    return subprocess.run(
        [sys.executable, "-m", "dietrich", *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def run_module(
    module: str,
    *args: str,
    check: bool = False,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``python -m <module>`` (e.g. dietrich)."""
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def normalize_capture(text: str, *, display_name: str | None = None) -> str:
    """Stabilize CLI output for docs: strip absolute paths and trailing spaces."""
    out = text.replace("\r\n", "\n")
    # Collapse absolute paths under the repo when present
    out = out.replace(str(ROOT) + "/", "")
    out = out.replace(str(ROOT), ".")
    if display_name:
        # Prefer a short document label for inspect lines
        out = re.sub(
            r"(?m)^Document: .+$",
            f"Document: {display_name}",
            out,
            count=1,
        )
        out = re.sub(
            r"(?m)^Wrote: .+$",
            f"Wrote: {display_name}",
            out,
            count=1,
        )
    # Trim trailing whitespace per line; keep final newline
    lines = [line.rstrip() for line in out.splitlines()]
    return "\n".join(lines).rstrip() + "\n"


def write_signed_xlsx(path: Path) -> Path:
    """Minimal OOXML with a signature part (rejected unless --strip-signatures)."""
    return write_ooxml(
        path,
        {
            "xl/workbook.xml": (
                b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<workbookProtection lockStructure="1"/><sheets/></workbook>'
            ),
            "xl/worksheets/sheet1.xml": (
                b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<sheetProtection sheet="1"/><sheetData/></worksheet>'
            ),
            "_xmlsignatures/sig1.xml": b"<Signature/>",
        },
    )


def write_irm_like_xlsx(path: Path) -> Path:
    """Synthetic package that trips IRM detection (not a real IRM file)."""
    return write_ooxml(
        path,
        {
            "xl/workbook.xml": b"<workbook/>",
            "customXml/item1.xml": b"<root>MicrosoftRightsManagement something</root>",
        },
    )


def make_self_signed_pem(tmp: Path) -> tuple[Path, Path]:
    """Return (cert_pem, key_pem) for honest re-sign demos."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Dietrich Demo")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7))
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp / "demo-cert.pem"
    key_pem = tmp / "demo-key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_pem, key_pem


def make_restricted_pdf(path: Path) -> Path:
    """PDF with owner restrictions (empty user password)."""
    import pikepdf

    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    pdf.save(
        path,
        encryption=pikepdf.Encryption(
            owner="owner-secret",
            user="",
            allow=pikepdf.Permissions(extract=False, modify_annotation=False),
        ),
    )
    return path


def make_user_locked_pdf(path: Path, password: str = "demo") -> Path:
    """PDF requiring a user password."""
    import pikepdf

    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    pdf.save(path, encryption=pikepdf.Encryption(user=password, owner="ownerpw", R=4))
    return path
