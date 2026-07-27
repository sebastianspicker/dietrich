"""In-memory session recent-files list for the Filing Bench rail.

Local session only - no disk persistence, no network index.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Compact monogram for the session rail (Filing Bench mockup).
_SUFFIX_MARK = {
    ".xlsx": "X",
    ".xlsm": "X",
    ".xls": "X",
    ".docx": "W",
    ".docm": "W",
    ".doc": "W",
    ".pptx": "P",
    ".pptm": "P",
    ".ppt": "P",
    ".pdf": "PDF",
}

DEFAULT_MAX_RECENT = 12


@dataclass(frozen=True)
class RecentEntry:
    """One recent document in the local TUI session."""

    path: Path
    mark: str
    name: str
    note: str = ""

    @property
    def option_id(self) -> str:
        """Stable OptionList id (resolved path string)."""
        return str(self.path)

    def prompt(self) -> str:
        """Two-line OptionList prompt: mark + name, optional note."""
        head = f"{self.mark}  {self.name}"
        if self.note:
            return f"{head}\n    {self.note}"
        return head


class RecentSession:
    """MRU list of local paths for the current TUI process."""

    def __init__(self, *, max_items: int = DEFAULT_MAX_RECENT) -> None:
        """Cap how many recent paths are retained in this session."""
        self._max_items = max(1, int(max_items))
        self._items: list[RecentEntry] = []

    def __len__(self) -> int:
        """Number of remembered entries."""
        return len(self._items)

    def items(self) -> tuple[RecentEntry, ...]:
        """MRU-first snapshot."""
        return tuple(self._items)

    def remember(
        self,
        path: Path | str,
        *,
        note: str | None = None,
    ) -> RecentEntry:
        """Move path to front (or insert). Returns the entry stored."""
        resolved = Path(path).expanduser()
        try:
            resolved = resolved.resolve()
        except OSError:
            # Unresolved is fine for display; keep expanded form.
            pass

        mark = file_mark(resolved)
        name = resolved.name or str(resolved)
        clean_note = (note or "").strip()

        # Drop existing entry for the same path (re-insert at front).
        self._items = [e for e in self._items if e.path != resolved]
        entry = RecentEntry(path=resolved, mark=mark, name=name, note=clean_note)
        self._items.insert(0, entry)
        del self._items[self._max_items :]
        return entry

    def get(self, option_id: str) -> RecentEntry | None:
        """Look up an entry by OptionList option id."""
        for entry in self._items:
            if entry.option_id == option_id:
                return entry
        return None

    def clear(self) -> None:
        """Drop all session recent entries (tests / reset)."""
        self._items.clear()


def file_mark(path: Path) -> str:
    """Return a short monogram for a document path."""
    return _SUFFIX_MARK.get(path.suffix.lower(), "·")


def note_from_inspection(
    *,
    encrypted: bool = False,
    soft_count: int = 0,
    signed: bool = False,
    owner_restrictions: bool = False,
) -> str:
    """One-line rail note from inspection facts (calm, exact)."""
    if encrypted:
        return "open password"
    if signed:
        return "signed"
    if owner_restrictions:
        return "owner restrictions"
    if soft_count:
        return f"soft locks · {soft_count}"
    return "inspected"
