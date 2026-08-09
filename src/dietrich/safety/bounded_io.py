"""Memory-bounded prefix reads for untrusted files and ZIP members."""

from __future__ import annotations

import zipfile
from pathlib import Path


def read_file_prefix(path: Path, limit: int) -> bytes:
    """Read at most ``limit`` bytes from a file without loading the full input."""
    if limit < 0:
        raise ValueError("prefix limit must be non-negative")
    with Path(path).open("rb", buffering=0) as handle:
        return handle.read(limit)


def read_zip_member_prefix(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    """Read at most ``limit`` decompressed bytes from a ZIP member."""
    if limit < 0:
        raise ValueError("prefix limit must be non-negative")
    with archive.open(name) as member:
        return member.read(limit)
