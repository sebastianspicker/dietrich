"""Atomic output publish (replace or exclusive link) to avoid clobber races."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from dietrich.errors import OutputExistsError


@contextmanager
def temporary_output_path(target_path: Path) -> Iterator[Path]:
    """Yield an adjacent temporary path and remove it unless publication consumed it."""
    target = Path(target_path)
    with tempfile.NamedTemporaryFile(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
        delete=False,
    ) as temporary_file:
        temp_path = Path(temporary_file.name)
    try:
        yield temp_path
    finally:
        temp_path.unlink(missing_ok=True)


def publish_output(temp_path: Path, target_path: Path, *, overwrite: bool) -> None:
    """Publish a verified temporary file without a TOCTOU overwrite race."""
    if overwrite:
        os.replace(temp_path, target_path)
        return

    try:
        os.link(temp_path, target_path)
    except FileExistsError as exc:
        raise OutputExistsError(f"{target_path} already exists.") from exc
    temp_path.unlink()
