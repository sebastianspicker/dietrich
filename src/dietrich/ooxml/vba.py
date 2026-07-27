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
        try:
            return _unlock_ole_vba(data)
        except Exception:
            pass

    return _clear_vba_keys_in_bytes(data)


def _unlock_ole_vba(data: bytes) -> tuple[bytes, int]:
    """Internal helper: _unlock_ole_vba."""
    import io

    import olefile

    bio = io.BytesIO(data)
    if not olefile.isOleFile(bio):
        return _clear_vba_keys_in_bytes(data)

    bio.seek(0)
    touched_total = 0
    # olefile cannot easily rewrite in place; extract PROJECT-like streams,
    # patch, and rebuild via rewriting all streams into a new OLE is heavy.
    # For alpha: patch stream bytes inside the CFBF by replacing equal-length
    # or shorter KEY= values in the raw container after locating stream data.
    with olefile.OleFileIO(bio) as ole:
        stream_names = ["/".join(s) for s in ole.listdir(streams=True, storages=False)]
        project_streams = [
            n for n in stream_names if n.lower().endswith("project") or n.lower() == "project"
        ]
        if not project_streams:
            # Fall back to scanning all streams for DPB=
            project_streams = stream_names

        patches: list[tuple[bytes, bytes]] = []
        for name in project_streams:
            parts = name.split("/")
            raw = ole.openstream(parts).read()
            if not any(k in raw for k in (b"DPB", b"CMG", b"GC", b"dpb", b"cmg")):
                continue
            patched, n = _clear_vba_keys_in_bytes(raw)
            if n and len(patched) == len(raw):
                # Same-length patch can be applied in the outer CFBF by replace
                if patched != raw:
                    patches.append((raw, patched))
                    touched_total += n
            elif n and len(patched) != len(raw):
                # Length-changing: still apply global replace of original segment
                patches.append((raw, patched))
                touched_total += n

    result = data
    for old, new in patches:
        if old in result:
            result = result.replace(old, new, 1)
        elif len(old) == len(new):
            # try find longest common - skip if not found
            pass

    if touched_total:
        return result, touched_total
    return _clear_vba_keys_in_bytes(data)


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
