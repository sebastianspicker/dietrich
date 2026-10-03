"""OLE/CFB stream read and same-size in-place stream rewrite helpers.

Used by binary soft unlock to patch Workbook/WordDocument streams without a
full CFB re-encoder.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dietrich.operation import checkpoint

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# CFBF directory metadata is attacker-controlled.  These limits are applied
# before loading the compound file or any stream into memory.
MAX_CFB_INPUT_BYTES = 512 * 1024 * 1024
MAX_CFB_STREAMS = 10_000
MAX_CFB_STREAM_BYTES = 128 * 1024 * 1024
MAX_CFB_TOTAL_STREAM_BYTES = 256 * 1024 * 1024


def read_streams(path: Path) -> dict[str, bytes]:
    """Return {stream_path: data} for all streams in an OLE file."""
    import olefile

    path = Path(path)
    _require_input_size(path)
    streams: dict[str, bytes] = {}
    with olefile.OleFileIO(str(path)) as ole:
        entries = _validated_stream_entries(ole)
        for entry in entries:
            checkpoint()
            name = "/".join(entry)
            streams[name] = _read_stream_limited(ole, entry)
    return streams


def validate_cfb(path: Path) -> None:
    """Validate CFB metadata and allocation chains without reading stream contents.

    This is intentionally a bounded check for decrypted-output publication.
    ``OleFileIO`` parses the header, allocation tables, and directory entries,
    while this function never calls ``openstream`` or reads user streams.
    """
    import olefile

    path = Path(path)
    _require_input_size(path)
    if not olefile.isOleFile(str(path)):
        raise ValueError(f"{path} is not an OLE/CFB file")
    with olefile.OleFileIO(str(path)) as ole:
        _validated_stream_entries(ole)


def list_stream_names(path: Path) -> set[str]:
    """Return bounded CFB stream names without reading stream contents."""
    import olefile

    path = Path(path)
    _require_input_size(path)
    if not olefile.isOleFile(str(path)):
        raise ValueError(f"{path} is not an OLE/CFB file")
    with olefile.OleFileIO(str(path)) as ole:
        return {"/".join(entry) for entry in _validated_stream_entries(ole)}


def _require_input_size(path: Path) -> None:
    """Reject compound files before an OLE parser can load oversized inputs."""
    size = path.stat().st_size
    if size > MAX_CFB_INPUT_BYTES:
        raise ValueError(f"CFB input exceeds the {MAX_CFB_INPUT_BYTES}-byte processing limit")


def _bounded_stream_entries(ole) -> list[list[str]]:
    """Validate stream count and declared sizes before any stream reads."""
    entries = ole.listdir(streams=True, storages=False)
    if len(entries) > MAX_CFB_STREAMS:
        raise ValueError(f"CFB contains more than {MAX_CFB_STREAMS} streams")
    total = 0
    for entry in entries:
        checkpoint()
        size = int(ole.get_size(entry))
        if size > MAX_CFB_STREAM_BYTES:
            raise ValueError(
                f"CFB stream {'/'.join(entry)!r} exceeds the "
                f"{MAX_CFB_STREAM_BYTES}-byte processing limit"
            )
        total += size
        if total > MAX_CFB_TOTAL_STREAM_BYTES:
            raise ValueError(
                "CFB aggregate stream size exceeds the "
                f"{MAX_CFB_TOTAL_STREAM_BYTES}-byte processing limit"
            )
    return entries


def _validated_stream_entries(ole) -> list[list[str]]:
    """Validate directory limits plus every stream allocation chain."""
    entries = _bounded_stream_entries(ole)
    _validate_allocation_chains(ole, entries)
    return entries


def _validate_allocation_chains(ole, entries: list[list[str]]) -> None:
    """Reject unsafe root, FAT, and MiniFAT chains before any stream read."""
    root = ole.root
    if int(root.size) > MAX_CFB_STREAM_BYTES:
        raise ValueError("CFB mini stream exceeds the processing limit")
    _bounded_sector_chain(ole, root)
    for entry in entries:
        checkpoint()
        dirent = _dirent_for(ole, entry)
        if dirent is None:
            raise ValueError(f"CFB stream {'/'.join(entry)!r} has no directory entry")
        _bounded_sector_chain(ole, dirent)


def _read_stream_limited(ole, entry) -> bytes:
    """Read one metadata-bounded stream and reject size inconsistencies."""
    expected_size = int(ole.get_size(entry))
    if expected_size > MAX_CFB_STREAM_BYTES:
        raise ValueError("CFB stream exceeds the processing limit")
    stream = ole.openstream(entry)
    data = stream.read(expected_size + 1)
    if len(data) != expected_size:
        raise ValueError(f"CFB stream {'/'.join(entry)!r} has an invalid declared size")
    return data


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
    _require_input_size(path)
    validate_cfb(path)
    with path.open("rb", buffering=0) as source:
        data = bytearray(source.read(MAX_CFB_INPUT_BYTES + 1))
    if len(data) > MAX_CFB_INPUT_BYTES:
        raise ValueError("CFB input exceeds the processing limit")

    with olefile.OleFileIO(str(path)) as ole:
        applied: list[str] = []
        ole_runtime: Any = ole
        _validated_stream_entries(ole)

        context = _PatchContext(
            ole=ole,
            data=data,
            sector_size=int(ole_runtime.sectorsize),
            mini_size=int(ole_runtime.minisectorsize),
        )

        for name, new_bytes in patches.items():
            checkpoint()
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
    root_chain = _bounded_sector_chain(ole, root)
    _poke_file_chain(data, root_chain, sector_size, bytes(mini_stream))


def _patch_entry(context: _PatchContext, entry_path: Any, name: str, new_bytes: bytes) -> None:
    """Patch one resolved stream using the shared patch context."""
    old = _read_stream_limited(context.ole, entry_path)
    if len(new_bytes) != len(old):
        raise ValueError(
            f"stream {name!r} length changed {len(old)} -> {len(new_bytes)}; "
            "in-place patch requires equal length"
        )
    dirent = _dirent_for(context.ole, entry_path)
    if dirent is None:
        raise ValueError(f"directory entry not found for {name}")
    chain = _bounded_sector_chain(context.ole, dirent)
    if dirent.is_minifat:
        _poke_chain(context.load_mini_stream(), chain, context.mini_size, new_bytes)
        context.mini_dirty = True
        return
    _poke_file_chain(context.data, chain, context.sector_size, new_bytes)


def _resolve_entry(ole, name: str):
    """Resolve an exact stream path, with unique fallback for bare names only."""
    normalized = str(name).replace("\\", "/")
    exact = normalized.split("/")
    if _dirent_for(ole, exact) is not None:
        return exact
    if len(exact) > 1:
        return None
    matches = [
        entry
        for entry in ole.listdir(streams=True, storages=False)
        if entry[-1].lower() == normalized.lower()
    ]
    if len(matches) > 1:
        raise ValueError(f"ambiguous CFB stream name {name!r}")
    if matches:
        return matches[0]
    return None


def _dirent_for(ole, entry_path):
    """Resolve one stream through its complete case-insensitive storage path."""
    parts = (
        list(entry_path)
        if isinstance(entry_path, list | tuple)
        else str(entry_path).replace("\\", "/").split("/")
    )
    node = ole.root
    for part in parts:
        node = next(
            (child for child in node.kids if child.name.lower() == part.lower()),
            None,
        )
        if node is None:
            return None
    return node if int(getattr(node, "entry_type", -1)) == 2 else None


def _bounded_sector_chain(ole, dirent) -> list[int]:
    """Build one exact-size FAT or MiniFAT chain with cycle and index checks."""
    size = int(dirent.size)
    if size < 0 or size > MAX_CFB_STREAM_BYTES:
        raise ValueError("CFB stream size exceeds the processing limit")
    if size == 0:
        return []
    if dirent.is_minifat:
        if not ole.minifat:
            _load_minifat_bounded(ole)
        table = ole.minifat
        unit_size = int(ole.minisectorsize)
    else:
        table = ole.fat
        unit_size = int(ole.sectorsize)
    expected = (size + unit_size - 1) // unit_size
    return _bounded_index_chain(
        table,
        int(dirent.isectStart),
        expected,
        label="CFB sector chain",
    )


def _bounded_index_chain(
    table,
    start: int,
    expected: int,
    *,
    label: str,
) -> list[int]:
    """Traverse exactly ``expected`` table entries with cycle and index checks."""
    current = start
    end_of_chain = 0xFFFFFFFE
    seen: set[int] = set()
    chain: list[int] = []
    for _ in range(expected):
        checkpoint()
        if current == end_of_chain:
            raise ValueError(f"{label} ends before the declared size")
        if current < 0 or current >= len(table):
            raise ValueError(f"{label} contains an invalid sector index")
        if current in seen:
            raise ValueError(f"{label} contains a cycle")
        seen.add(current)
        chain.append(current)
        current = int(table[current])
    if current != end_of_chain:
        raise ValueError(f"{label} exceeds the declared size")
    return chain


def _load_minifat_bounded(ole) -> None:
    """Bound the dependency's MiniFAT table read before loading it."""
    sector_size = int(ole.sectorsize)
    sector_count = int(ole.num_mini_fat_sectors)
    if sector_count < 0 or sector_count * sector_size > MAX_CFB_STREAM_BYTES:
        raise ValueError("CFB MiniFAT exceeds the processing limit")
    _bounded_index_chain(
        ole.fat,
        int(ole.minifatsect),
        sector_count,
        label="CFB MiniFAT chain",
    )
    ole.loadminifat()


def _poke_file_chain(
    data: bytearray,
    chain: list[int],
    sector_size: int,
    new_bytes: bytes,
) -> None:
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
    offset = 0
    remaining = len(new_bytes)
    for sect in chain:
        if sect >= 0xFFFFFFFA:
            break
        off = sect * sector_size
        chunk = min(sector_size, remaining)
        if off + chunk > len(buf):
            raise ValueError("mini sector offset past end of root stream")
        buf[off : off + chunk] = new_bytes[offset : offset + chunk]
        offset += chunk
        remaining -= chunk
        if remaining <= 0:
            return
    if remaining != 0:
        raise ValueError("mini sector chain shorter than stream")


def _read_root_stream(ole, data: bytearray, sector_size: int) -> bytes:
    root = ole.direntries[0]
    if root.size > MAX_CFB_STREAM_BYTES:
        raise ValueError("CFB mini stream exceeds the processing limit")
    chain = _bounded_sector_chain(ole, root)
    parts: list[bytes] = []
    total = root.size
    got = 0
    for sect in chain:
        if sect >= 0xFFFFFFFA or got >= total:
            break
        file_off = sector_size * (sect + 1)
        take = min(sector_size, total - got)
        if file_off + take > len(data):
            raise ValueError("root mini stream sector offset past end of file")
        parts.append(bytes(data[file_off : file_off + take]))
        got += take
    if got != total:
        raise ValueError("root mini stream chain is shorter than its declared size")
    return b"".join(parts)
