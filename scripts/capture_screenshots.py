#!/usr/bin/env python3
"""Refresh CLI text captures and deterministic Textual TUI SVG captures.

Usage (repo root, venv with .[full]):

    python scripts/capture_screenshots.py
    python scripts/capture_screenshots.py --check   # assert key captures exist + non-empty

Pathnames in captures are normalized to short display names for stable docs.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.support.cli import (  # noqa: E402
    make_restricted_pdf,
    normalize_capture,
    run_dietrich,
    write_signed_xlsx,
)
from tests.support.fixtures import ENCRYPTED_XLSX, KNOWN_PASSWORD, PLAIN_XLS  # noqa: E402
from tests.support.ooxml import protected_xlsx  # noqa: E402

SHOTS = ROOT / "docs" / "screenshots"


def _write(name: str, body: str) -> Path:
    """Write one capture file under docs/screenshots/."""
    path = SHOTS / name
    path.write_text(body if body.endswith("\n") else body + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(body)} bytes)")
    return path


def _strip_renderer_comment(path: Path) -> None:
    """Remove non-visible renderer provenance from a committed capture."""
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text(
        "".join(line for line in lines if "textualize.io" not in line),
        encoding="utf-8",
    )


async def _wait_for_tui(app, pilot) -> None:
    """Wait for the TUI's current background operation to complete."""
    for _ in range(100):
        if not app.is_busy:
            await pilot.pause(0.05)
            return
        await pilot.pause(0.05)
    raise RuntimeError("TUI capture did not become ready")


async def _capture_tui_screens(protected: Path) -> list[Path]:
    """Render stable Werkbank SVGs from real Textual application states."""
    from datetime import datetime as real_datetime

    from textual.widgets import Input

    import dietrich.tui.app as tui_app

    class CaptureDateTime:
        """Fixed activity clock so committed SVGs are reproducible."""

        @classmethod
        def now(cls):
            """Return the fixed capture timestamp."""
            return real_datetime(2026, 7, 22, 9, 42, 18)

    original_datetime = tui_app.datetime
    tui_app.datetime = CaptureDateTime
    written: list[Path] = []
    try:
        written.append(await _capture_empty_tui(tui_app))
        written.append(await _capture_inspected_tui(tui_app, Input, protected))
        written.append(await _capture_encrypted_tui(tui_app, Input))
    finally:
        tui_app.datetime = original_datetime
    for path in written:
        _strip_renderer_comment(path)
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")
    return written


async def _capture_empty_tui(tui_app) -> Path:
    """Capture the deterministic empty terminal UI state."""
    app = tui_app.DietrichApp()
    async with app.run_test(size=(140, 40)) as pilot:
        await _wait_for_tui(app, pilot)
        return Path(app.save_screenshot(filename="werkbank-tui-chrome.svg", path=str(SHOTS)))


async def _capture_inspected_tui(tui_app, input_widget, protected: Path) -> Path:
    """Capture the protected-workbook inspection state."""
    app = tui_app.DietrichApp(initial_path=protected)
    async with app.run_test(size=(160, 50)) as pilot:
        await _wait_for_tui(app, pilot)
        app.query_one("#input-path", input_widget).value = "examples/out/protected.xlsx"
        app.query_one("#output-path", input_widget).value = (
            "examples/out/protected_unprotected.xlsx"
        )
        await pilot.pause(0.05)
        return Path(app.save_screenshot(filename="werkbank-tui-smoke.svg", path=str(SHOTS)))


async def _capture_encrypted_tui(tui_app, input_widget) -> Path:
    """Capture the encrypted-workbook state after a real hash export."""
    app = tui_app.DietrichApp(initial_path=ENCRYPTED_XLSX)
    async with app.run_test(size=(160, 50)) as pilot:
        await _wait_for_tui(app, pilot)
        app.action_export_hash()
        await _wait_for_tui(app, pilot)
        app.query_one("#input-path", input_widget).value = "examples/out/encrypted.xlsx"
        app.query_one("#output-path", input_widget).value = (
            "examples/out/encrypted_unprotected.xlsx"
        )
        await pilot.pause(0.05)
        return Path(app.save_screenshot(filename="werkbank-tui-smoke-export.svg", path=str(SHOTS)))


def capture_tui_screens(protected: Path) -> list[Path]:
    """Render TUI captures with true color even when the caller sets NO_COLOR."""
    no_color = os.environ.pop("NO_COLOR", None)
    try:
        return asyncio.run(_capture_tui_screens(protected))
    finally:
        if no_color is not None:
            os.environ["NO_COLOR"] = no_color


def capture_all() -> list[Path]:
    """Run demo CLI commands and write normalized text captures under docs/screenshots/."""
    SHOTS.mkdir(parents=True, exist_ok=True)
    written = _capture_help()
    work = Path(tempfile.mkdtemp(prefix="dietrich-shots-"))
    try:
        written.extend(_capture_cli_groups(work))
        soft = work / "protected.xlsx"
        written.extend(capture_tui_screens(soft))

    finally:
        shutil.rmtree(work, ignore_errors=True)

    written.append(_write("README.md", _capture_readme()))
    return written


def _capture_readme() -> str:
    """Return the deterministic capture index."""
    return """# Command and terminal captures

Refresh the command text and Textual SVG files with:

```bash
python -m pip install -e '.[full]'
python scripts/capture_screenshots.py
```

| File | Command or state |
|------|------|
| `01-help.txt` | `dietrich --help` |
| `02-inspect-encrypted.txt` | Inspect an Agile-encrypted fixture |
| `03-soft-xlsx.txt` | Remove protection from `.xlsx` |
| `04-soft-binary.txt` | Process a legacy `.xls` fixture |
| `05-password-unlock.txt` | Decrypt with an open password |
| `06-export-hash.txt` | `--export-hash hashcat` (truncated) |
| `07-pdf-permissions.txt` | Remove PDF encryption and permissions |
| `08-json-inspect.txt` | `--inspect --json` |
| `09-worksheets-only.txt` | Use `--worksheets-only` |
| `10-soft-only-error.txt` | Reject encryption with `--soft-only` |
| `11-strip-signatures.txt` | Reject and explicitly strip signatures |

## Textual TUI captures

The script renders these SVGs from fixed application states. Paths and activity
timestamps are normalized:

| File | State |
|------|---------|
| `werkbank-tui-chrome.svg` | Empty interface at 140 by 40 terminal cells |
| `werkbank-tui-smoke.svg` | Inspected protected workbook at 160 by 50 |
| `werkbank-tui-smoke-export.svg` | Encrypted workbook after hash export at 160 by 50 |

The recent-path rail appears in sufficiently wide terminals and stores paths only
for the current process.

Run `dietrich --tui` after installing the `ui` or `full` extra for an interactive
check.

## Fixtures

- `tests/fixtures/example_password.xlsx` (password `Password1234_`)
- `tests/fixtures/plain.xls`
- OOXML and PDF files created in a temporary directory during capture

Captured paths do not contain machine-local absolute paths.
"""


def _capture_help() -> list[Path]:
    """Capture the help output."""
    return [_write("01-help.txt", normalize_capture(run_dietrich("--help").stdout))]


def _capture_cli_groups(work: Path) -> list[Path]:
    """Capture CLI examples in their documented order."""
    written = _capture_inspect_and_soft(work)
    written.extend(_capture_password_group(work))
    written.extend(_capture_pdf_and_json(work))
    written.append(_capture_signed(work))
    return written


def _capture_inspect_and_soft(work: Path) -> list[Path]:
    """Capture encrypted inspection and soft unlock examples."""
    written: list[Path] = []
    if ENCRYPTED_XLSX.is_file():
        insp = run_dietrich(str(ENCRYPTED_XLSX), "--inspect")
        written.append(_write(
            "02-inspect-encrypted.txt", normalize_capture(insp.stdout, display_name="secret.xlsx")
        ))
    soft = protected_xlsx(work / "protected.xlsx")
    out_soft = work / "protected_unprotected.xlsx"
    soft_run = run_dietrich(str(soft), "--output", str(out_soft))
    combined = soft_run.stdout + soft_run.stderr if soft_run.stderr else soft_run.stdout
    written.append(_write(
        "03-soft-xlsx.txt", normalize_capture(combined, display_name="protected_unprotected.xlsx")
    ))
    if PLAIN_XLS.is_file():
        out_bin = work / "plain_unprotected.xls"
        bin_run = run_dietrich(str(PLAIN_XLS), "--output", str(out_bin))
        written.append(_write(
            "04-soft-binary.txt",
            normalize_capture(bin_run.stdout, display_name="plain_unprotected.xls"),
        ))
    return written


def _capture_password_group(work: Path) -> list[Path]:
    """Capture password, hash export, and soft-only examples."""
    if not ENCRYPTED_XLSX.is_file():
        return []
    out_pw = work / "secret_unprotected.xlsx"
    pw_run = run_dietrich(
        str(ENCRYPTED_XLSX), "--password", KNOWN_PASSWORD, "--output", str(out_pw)
    )
    written = [_write(
        "05-password-unlock.txt",
        normalize_capture(pw_run.stdout, display_name="secret_unprotected.xlsx"),
    )]
    line = run_dietrich(str(ENCRYPTED_XLSX), "--export-hash", "hashcat").stdout.strip()
    if len(line) > 120:
        line = line[:100] + "…"
    written.append(_write("06-export-hash.txt", line + "\n"))
    soft_only = run_dietrich(
        str(ENCRYPTED_XLSX), "--soft-only", "--output", str(work / "nope.xlsx")
    )
    err = soft_only.stderr.strip() or soft_only.stdout.strip()
    written.append(_write("10-soft-only-error.txt", normalize_capture(err + "\n")))
    return written


def _capture_pdf_and_json(work: Path) -> list[Path]:
    """Capture PDF, JSON inspection, and worksheet-only examples."""
    try:
        pdf = make_restricted_pdf(work / "restricted.pdf")
        out_pdf = work / "restricted_unprotected.pdf"
        pdf_run = run_dietrich(str(pdf), "--output", str(out_pdf))
        written = [_write(
            "07-pdf-permissions.txt",
            normalize_capture(pdf_run.stdout, display_name="restricted_unprotected.pdf"),
        )]
    except ModuleNotFoundError as exc:
        if exc.name != "pikepdf":
            raise
        written = [_write(
            "07-pdf-permissions.txt", f"(skipped: PDF demo requires pikepdf: {exc})\n"
        )]
    soft2 = protected_xlsx(work / "json.xlsx")
    body = run_dietrich(str(soft2), "--inspect", "--json").stdout.replace(
        str(soft2), "protected.xlsx"
    )
    written.append(_write("08-json-inspect.txt", normalize_capture(body)))
    soft3 = protected_xlsx(work / "sheets_only.xlsx")
    out_ws = work / "sheets_only_out.xlsx"
    ws_run = run_dietrich(str(soft3), "--worksheets-only", "--output", str(out_ws))
    written.append(_write(
        "09-worksheets-only.txt",
        normalize_capture(ws_run.stdout, display_name="sheets_only_out.xlsx"),
    ))
    return written


def _capture_signed(work: Path) -> Path:
    """Capture signature rejection and explicit stripping."""
    signed = write_signed_xlsx(work / "signed.xlsx")
    blocked = run_dietrich(str(signed), "--output", str(work / "blocked.xlsx"))
    stripped = run_dietrich(
        str(signed), "--strip-signatures", "--output", str(work / "unsigned.xlsx"), "--force"
    )
    text = (
        "# Without --strip-signatures (fails):\n"
        f"{(blocked.stderr or blocked.stdout).strip()}\n\n"
        "# With --strip-signatures --force:\n"
        f"{normalize_capture(stripped.stdout.strip(), display_name='unsigned.xlsx').rstrip()}\n"
    )
    return _write("11-strip-signatures.txt", text)


def check_captures() -> int:
    """Return 0 if expected captures exist and look non-empty."""
    required = [
        "01-help.txt",
        "02-inspect-encrypted.txt",
        "03-soft-xlsx.txt",
        "04-soft-binary.txt",
        "05-password-unlock.txt",
        "06-export-hash.txt",
        "07-pdf-permissions.txt",
        "08-json-inspect.txt",
        "09-worksheets-only.txt",
        "10-soft-only-error.txt",
        "11-strip-signatures.txt",
        "werkbank-tui-chrome.svg",
        "werkbank-tui-smoke.svg",
        "werkbank-tui-smoke-export.svg",
        "README.md",
    ]
    missing = []
    for name in required:
        path = SHOTS / name
        if not path.is_file() or path.stat().st_size < 10:
            missing.append(name)
    if missing:
        print("missing or empty captures:", ", ".join(missing), file=sys.stderr)
        return 1
    # content smoke
    help_txt = (SHOTS / "01-help.txt").read_text(encoding="utf-8")
    if "Dietrich" not in help_txt:
        print("01-help.txt does not look like dietrich --help", file=sys.stderr)
        return 1

    print(f"ok: {len(required)} captures present under {SHOTS.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry: regenerate captures or --check committed files."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only verify committed captures exist (no regenerate)",
    )
    args = parser.parse_args(argv)
    if args.check:
        return check_captures()
    capture_all()
    return check_captures()


if __name__ == "__main__":
    raise SystemExit(main())
