"""Clear VBA project password verifier fields (CMG/DPB/GC) when present as text."""

from __future__ import annotations

import re

_VBA_KEYS = (b"CMG", b"DPB", b"GC")
_LINE_RE = re.compile(
    rb"(?P<key>CMG|DPB|GC)\s*=\s*(?P<val>[^\r\n]*)",
    re.IGNORECASE,
)


def unlock_vba_project(data: bytes) -> tuple[bytes, int]:
    """Clear VBA project password verifier fields.

    Returns (new_bytes, number_of_fields_touched).
    """
    if not data:
        return data, 0

    # Prefer OLE PROJECT stream when compound file.
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        ole_result = _try_unlock_ole_vba(data)
        if ole_result is not None:
            return ole_result

    return _clear_vba_keys_in_bytes(data)


def _try_unlock_ole_vba(data: bytes) -> tuple[bytes, int] | None:
    """Attempt the optional OLE stream path and fall back only on malformed OLE data."""
    try:
        import olefile
    except ImportError:
        return None
    try:
        return _unlock_ole_vba(data, olefile)
    except (OSError, ValueError, olefile.olefile.OleFileError):
        return None


def _unlock_ole_vba(data: bytes, olefile) -> tuple[bytes, int]:
    """Internal helper: _unlock_ole_vba."""
    import io

    bio = io.BytesIO(data)
    if not olefile.isOleFile(bio):
        return _clear_vba_keys_in_bytes(data)

    bio.seek(0)
    with olefile.OleFileIO(bio) as ole:
        patches, touched_total = _ole_vba_patches(ole)
    result = _apply_ole_patches(data, patches)
    if touched_total:
        return result, touched_total
    return _clear_vba_keys_in_bytes(data)


def _ole_vba_patches(ole) -> tuple[list[tuple[bytes, bytes]], int]:
    """Read PROJECT-like OLE streams and collect raw-container replacements."""
    names = ["/".join(parts) for parts in ole.listdir(streams=True, storages=False)]
    project_streams = [name for name in names if name.lower().endswith("project")]
    candidates = project_streams or names
    patches: list[tuple[bytes, bytes]] = []
    touched_total = 0
    for name in candidates:
        raw = ole.openstream(name.split("/")).read()
        patched, touched = _clear_vba_keys_in_bytes(raw)
        if touched and patched != raw:
            patches.append((raw, patched))
            touched_total += touched
    return patches, touched_total


def _apply_ole_patches(data: bytes, patches: list[tuple[bytes, bytes]]) -> bytes:
    """Apply each verified raw stream replacement once in the outer CFBF bytes."""
    result = data
    for old, new in patches:
        if old in result:
            result = result.replace(old, new, 1)
    return result


def _clear_vba_keys_in_bytes(data: bytes) -> tuple[bytes, int]:
    """Replace CMG=/DPB=/GC= values with empty quoted string; pad if needed for length."""
    touched = 0

    def repl(match: re.Match[bytes]) -> bytes:
        """Regex replace callback for one CMG/DPB/GC field."""
        nonlocal touched
        key = match.group("key")
        # Prefer empty quoted form used by unlocked projects
        new_val = b'""'
        # Keep same total match length when possible to avoid shifting OLE streams
        old_full = match.group(0)
        new_full = key + b"=" + new_val
        if len(new_full) < len(old_full):
            new_full = new_full + b" " * (len(old_full) - len(new_full))
        elif len(new_full) > len(old_full):
            # cannot pad shorter source; use raw replacement
            new_full = key + b"=" + new_val
        if new_full != old_full:
            touched += 1
        return new_full

    result = _LINE_RE.sub(repl, data)
    return result, touched
