"""Unit tests for in-memory TUI recent-path history."""

from __future__ import annotations

from pathlib import Path

from dietrich.tui.session_history import (
    RecentSession,
    file_mark,
    note_from_inspection,
)


def test_file_mark_by_suffix() -> None:
    assert file_mark(Path("a.xlsx")) == "X"
    assert file_mark(Path("b.DOCX")) == "W"
    assert file_mark(Path("c.pptx")) == "P"
    assert file_mark(Path("d.pdf")) == "PDF"
    assert file_mark(Path("e.bin")) == "·"


def test_note_from_inspection_priority() -> None:
    assert note_from_inspection(encrypted=True, soft_count=3) == "open password"
    assert note_from_inspection(signed=True) == "signed"
    assert note_from_inspection(owner_restrictions=True) == "owner restrictions"
    assert note_from_inspection(soft_count=2) == "soft locks · 2"
    assert note_from_inspection() == "inspected"


def test_remember_mru_and_dedupe(tmp_path: Path) -> None:
    a = tmp_path / "a.xlsx"
    b = tmp_path / "b.docx"
    a.write_text("a")
    b.write_text("b")
    session = RecentSession(max_items=3)
    session.remember(a, note="first")
    session.remember(b, note="second")
    session.remember(a, note="again")
    items = session.items()
    assert len(items) == 2
    assert items[0].name == "a.xlsx"
    assert items[0].note == "again"
    assert items[1].name == "b.docx"


def test_max_items_cap(tmp_path: Path) -> None:
    session = RecentSession(max_items=2)
    paths = []
    for i in range(4):
        p = tmp_path / f"f{i}.xlsx"
        p.write_text("x")
        paths.append(p)
        session.remember(p)
    assert len(session) == 2
    names = [e.name for e in session.items()]
    assert names == ["f3.xlsx", "f2.xlsx"]


def test_get_by_option_id(tmp_path: Path) -> None:
    p = tmp_path / "report.xlsx"
    p.write_text("x")
    session = RecentSession()
    entry = session.remember(p, note="soft locks · 1")
    assert session.get(entry.option_id) is entry
    assert session.get("missing") is None
    assert "report.xlsx" in entry.prompt()
    assert "soft locks" in entry.prompt()
