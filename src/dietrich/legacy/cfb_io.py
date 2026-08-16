"""OLE/CFB stream read and same-size in-place stream rewrite helpers.

Used by binary soft unlock to patch Workbook/WordDocument streams without a
full CFB re-encoder.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


def validate_cfb(path: Path) -> None:
    """Validate CFB header and directory metadata without reading stream contents.

    This is intentionally a bounded check for decrypted-output publication.
    ``OleFileIO`` parses the header, allocation tables, and directory entries,
    while this function never calls ``openstream`` or reads user streams.
    """
    import olefile

    path = Path(path)
    if not olefile.isOleFile(str(path)):
        raise ValueError(f"{path} is not an OLE/CFB file")
    with olefile.OleFileIO(str(path)) as ole:
        ole.listdir(streams=True, storages=False)


@dataclass
class _PatchContext:
    """Mutable state shared while applying equal-size CFB stream patches."""

    ole: Any
    data: bytearray
    sector_size: int
    mini_size: int
    mini_stream: bytearray | None = None
    mini_dirty: bool = False

    def load_mini_stream(self) -> bytearray:
        """Return the cached root mini stream, loading it once when required."""
        if self.mini_stream is None:
            self.mini_stream = bytearray(_read_root_stream(self.ole, self.data, self.sector_size))
        return self.mini_stream

    def flush_mini_stream(self) -> None:
        """Flush an updated mini stream through the root directory chain."""
        if self.mini_dirty and self.mini_stream is not None:
            _flush_mini_stream(self.ole, self.data, self.sector_size, self.mini_stream)


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
        applied: list[str] = []
        ole_runtime: Any = ole

        context = _PatchContext(
            ole=ole,
            data=data,
            sector_size=int(ole_runtime.sectorsize),
            mini_size=int(ole_runtime.minisectorsize),
        )

        for name, new_bytes in patches.items():
            entry_path = _resolve_entry(ole, name)
            if entry_path is None:
                continue
            _patch_entry(context, entry_path, name, new_bytes)

            applied.append(
                "/".join(entry_path) if isinstance(entry_path, list | tuple) else str(entry_path)
            )

        context.flush_mini_stream()

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


def _patch_entry(context: _PatchContext, entry_path: Any, name: str, new_bytes: bytes) -> None:
    """Patch one resolved stream using the shared patch context."""
    old = context.ole.openstream(entry_path).read()
    if len(new_bytes) != len(old):
        raise ValueError(
            f"stream {name!r} length changed {len(old)} -> {len(new_bytes)}; "
            "in-place patch requires equal length"
        )
    dirent = _dirent_for(context.ole, entry_path)
    if dirent is None:
        raise ValueError(f"directory entry not found for {name}")
    if hasattr(dirent, "build_sect_chain"):
        dirent.build_sect_chain(context.ole)
    chain = list(dirent.sect_chain or [])
    if dirent.is_minifat:
        _poke_chain(context.load_mini_stream(), chain, context.mini_size, new_bytes)
        context.mini_dirty = True
        return
    _poke_file_chain(context.data, chain, context.sector_size, new_bytes)


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
) -> None:
    """Internal helper: _poke_chain."""
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
