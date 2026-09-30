"""Transaction-local metadata reuse for explicitly registered private snapshots."""

from __future__ import annotations

from contextvars import ContextVar, Token
from pathlib import Path

# Only transaction-owned input snapshots are eligible. New candidates never are.
_SNAPSHOTS: ContextVar[dict[Path, tuple[int, ...] | None] | None] = ContextVar(
    "dietrich_snapshots", default=None
)


def begin_snapshots() -> Token:
    return _SNAPSHOTS.set({})


def end_snapshots(token: Token) -> None:
    _SNAPSHOTS.reset(token)


def register_snapshot(path: Path) -> None:
    snapshots = _SNAPSHOTS.get()
    if snapshots is not None:
        snapshots[path] = None


def snapshot_checked(path: str | Path | None, *, remember: bool = False) -> bool:
    """Reuse successful ZIP metadata checks only while snapshot identity is stable."""
    snapshots = _SNAPSHOTS.get()
    if snapshots is None or path is None or Path(path) not in snapshots:
        return False
    source = Path(path)
    stat = source.stat()
    identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    checked = snapshots[source] == identity
    if remember:
        snapshots[source] = identity
    return checked
