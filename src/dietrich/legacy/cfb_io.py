"""OLE/CFB stream read and same-size in-place stream rewrite helpers.

Used by binary soft unlock to patch Workbook/WordDocument streams without a
full CFB re-encoder.
"""

from __future__ import annotations

from pathlib import Path

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def read_streams(path: Path) -> dict[str, bytes]:
    """Return {stream_path: data} for all streams in an OLE file."""
    import olefile

    path = Path(path)
    streams: dict[str, bytes] = {}
    with olefile.OleFileIO(str(path)) as ole:
        for entry in ole.listdir(streams=True, storages=False):
            name = "/".join(entry)
            streams[name] = ole.openstream(entry).read()
    return streams


def patch_streams(path: Path, output_path: Path, patches: dict[str, bytes]) -> list[str]:
    """Patch named streams (equal-length only) and write output_path.

    Uses olefile sector chains to write stream bytes back into a full-file
    bytearray copy of the source CFB.
    """
    import olefile

    path = Path(path)
    output_path = Path(output_path)
    data = bytearray(path.read_bytes())

    with olefile.OleFileIO(str(path)) as ole:
        sector_size = ole.sectorsize
        mini_size = ole.minisectorsize
        applied: list[str] = []

        # Cache mini stream bytes if needed
        mini_stream: bytearray | None = None
        mini_dirty = False

        for name, new_bytes in patches.items():
            entry_path = _resolve_entry(ole, name)
            if entry_path is None:
                continue
            mini_stream, was_mini = _patch_entry(
                ole, entry_path, name, new_bytes, data, sector_size, mini_size, mini_stream
            )
            mini_dirty = mini_dirty or was_mini

            applied.append(
                "/".join(entry_path) if isinstance(entry_path, list | tuple) else str(entry_path)
            )

        if mini_dirty and mini_stream is not None:
            _flush_mini_stream(ole, data, sector_size, mini_stream)

    if not applied:
        raise ValueError("no matching streams to patch")

    output_path.write_bytes(data)
    return applied


def _flush_mini_stream(ole, data: bytearray, sector_size: int, mini_stream: bytearray) -> None:
    """Write the updated mini stream through the root directory chain."""
    root = ole.direntries[0]
    if hasattr(root, "build_sect_chain"):
        root.build_sect_chain(ole)
    root_chain = list(root.sect_chain or [])
    _poke_file_chain(data, root_chain, sector_size, bytes(mini_stream))


def _patch_entry(ole, entry_path, name, new_bytes, data, sector_size, mini_size, mini_stream):
    """Patch one resolved stream and return updated mini-stream state."""
    old = ole.openstream(entry_path).read()
    if len(new_bytes) != len(old):
        raise ValueError(
            f"stream {name!r} length changed {len(old)} -> {len(new_bytes)}; "
            "in-place patch requires equal length"
        )
    dirent = _dirent_for(ole, entry_path)
    if dirent is None:
        raise ValueError(f"directory entry not found for {name}")
    if hasattr(dirent, "build_sect_chain"):
        dirent.build_sect_chain(ole)
    chain = list(dirent.sect_chain or [])
    if dirent.is_minifat:
        if mini_stream is None:
            mini_stream = bytearray(_read_root_stream(ole, data, sector_size))
        _poke_chain(mini_stream, chain, mini_size, new_bytes, base=0)
        return mini_stream, True
    _poke_file_chain(data, chain, sector_size, new_bytes)
    return mini_stream, False


def _resolve_entry(ole, name: str):
    """Resolve a directory entry index to stream bytes."""
    if ole.exists(name):
        return name
    short = str(name).rsplit("/", maxsplit=1)[-1]
    for entry in ole.listdir(streams=True, storages=False):
        if entry[-1] == short or "/".join(entry) == name:
            return entry
    return None


def _dirent_for(ole, entry_path):
    """Internal helper: _dirent_for."""
    if isinstance(entry_path, list | tuple):
        short = entry_path[-1]
    else:
        short = str(entry_path).rsplit("/", maxsplit=1)[-1]
    for e in ole.direntries:
        if e and e.name == short:
            return e
    return None


def _poke_file_chain(
    data: bytearray,
    chain: list[int],
    sector_size: int,
    new_bytes: bytes,
) -> None:
    """Internal helper: _poke_file_chain."""
    offset = 0
    remaining = len(new_bytes)
    for sect in chain:
        if sect >= 0xFFFFFFFA:
            break
        file_off = sector_size * (sect + 1)
        chunk = min(sector_size, remaining)
        if file_off + chunk > len(data):
            raise ValueError("sector offset past end of file")
        data[file_off : file_off + chunk] = new_bytes[offset : offset + chunk]
        offset += chunk
        remaining -= chunk
        if remaining <= 0:
            return
    if remaining != 0:
        raise ValueError("sector chain shorter than stream")


def _poke_chain(
    buf: bytearray,
    chain: list[int],
    sector_size: int,
    new_bytes: bytes,
    *,
    base: int,
) -> None:
    """Internal helper: _poke_chain."""
    del base
    offset = 0
    remaining = len(new_bytes)
    for sect in chain:
        if sect >= 0xFFFFFFFA:
            break
        off = sect * sector_size
        chunk = min(sector_size, remaining)
        if off + chunk > len(buf):
            # extend mini stream buffer if needed
            buf.extend(b"\x00" * (off + chunk - len(buf)))
        buf[off : off + chunk] = new_bytes[offset : offset + chunk]
        offset += chunk
        remaining -= chunk
        if remaining <= 0:
            return
    if remaining != 0:
        raise ValueError("mini sector chain shorter than stream")


def _read_root_stream(ole, data: bytearray, sector_size: int) -> bytes:
    """Internal helper: _read_root_stream."""
    root = ole.direntries[0]
    if hasattr(root, "build_sect_chain"):
        root.build_sect_chain(ole)
    chain = list(root.sect_chain or [])
    parts: list[bytes] = []
    total = root.size
    got = 0
    for sect in chain:
        if sect >= 0xFFFFFFFA or got >= total:
            break
        file_off = sector_size * (sect + 1)
        take = min(sector_size, total - got)
        parts.append(bytes(data[file_off : file_off + take]))
        got += take
    return b"".join(parts)
