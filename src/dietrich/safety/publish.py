"""Atomic output publish (replace or exclusive link) to avoid clobber races."""

from __future__ import annotations

import os
from pathlib import Path

from dietrich.errors import OutputExistsError


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
