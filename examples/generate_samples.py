#!/usr/bin/env python3
"""Generate synthetic demo documents under examples/out/ for walkthroughs.

Does not copy private workbooks. Encrypted Office samples are copied from the
public files documented in tests/fixtures/README.md.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "out"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.support.cli import (  # noqa: E402
    make_restricted_pdf,
    make_user_locked_pdf,
    write_signed_xlsx,
)
from tests.support.fixtures import (  # noqa: E402
    ENCRYPTED_DOCX,
    ENCRYPTED_XLSX,
    PLAIN_DOC,
    PLAIN_PPT,
    PLAIN_XLS,
)
from tests.support.ooxml import protected_docx, protected_pptx, protected_xlsx  # noqa: E402


def main() -> int:
    """Build synthetic demos under examples/out/ and copy public fixtures."""
    OUT.mkdir(parents=True, exist_ok=True)
    # Soft-protected OOXML
    protected_xlsx(OUT / "protected.xlsx")
    protected_docx(OUT / "protected.docx")
    protected_pptx(OUT / "protected.pptx")
    write_signed_xlsx(OUT / "signed.xlsx")

    _write_pdf_demos()
    _copy_public_fixtures()
    _write_password_notes()
    print(f"samples ready under {OUT}")
    return 0


def _write_pdf_demos() -> None:
    """Generate optional PDF examples when pikepdf is installed."""
    try:
        make_restricted_pdf(OUT / "restricted.pdf")
        make_user_locked_pdf(OUT / "user_locked.pdf", password="demo")
        print("wrote PDF demos (restricted.pdf, user_locked.pdf password=demo)")
    except ModuleNotFoundError as exc:
        if exc.name != "pikepdf":
            raise
        print(f"skip PDF demos: {exc}", file=sys.stderr)


def _copy_public_fixtures() -> None:
    """Copy documented public Office fixtures into the demo directory."""
    copies = [
        (ENCRYPTED_XLSX, OUT / "encrypted.xlsx"),
        (ENCRYPTED_DOCX, OUT / "encrypted.docx"),
        (PLAIN_XLS, OUT / "plain.xls"),
        (PLAIN_DOC, OUT / "plain.doc"),
        (PLAIN_PPT, OUT / "plain.ppt"),
    ]
    for src, dest in copies:
        if src.is_file():
            shutil.copy2(src, dest)
            print(f"copied {src.name} -> {dest.name}")
        else:
            print(f"missing fixture {src}", file=sys.stderr)


def _write_password_notes() -> None:
    """Write the public demo credentials next to generated samples."""
    (OUT / "PASSWORDS.txt").write_text(
        "encrypted.xlsx / encrypted.docx: Password1234_\n"
        "user_locked.pdf: demo\n"
        "restricted.pdf: empty user password; owner restrictions only\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
