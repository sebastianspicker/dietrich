"""Experimental local-lab OOXML mutant generators (not a product unlock path).

The seeded generator intentionally makes a fuzz case reproducible. It is never
used for passwords, keys, or any other security-sensitive value.
"""

from __future__ import annotations

import random
import zipfile
from pathlib import Path

from dietrich.safety.zip_archive import validate_archive_safety


def generate_ooxml_mutants(
    seed_path: Path,
    out_dir: Path,
    *,
    count: int = 10,
    seed: int = 0,
) -> list[Path]:
    """Create mutated copies of an OOXML ZIP for local fuzzing."""
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    original = seed_path.read_bytes()
    outputs: list[Path] = []

    for i in range(count):
        data = bytearray(original)
        mode = i % 4
        if mode == 0 and len(data) > 64:
            # Bit flip in random locations
            for _ in range(rng.randint(1, 8)):
                pos = rng.randrange(len(data))
                data[pos] ^= 1 << rng.randrange(8)
        elif mode == 1:
            # Truncation
            cut = rng.randint(len(data) // 2, max(len(data) // 2 + 1, len(data) - 1))
            data = data[:cut]
        elif mode == 2:
            # Inject oversized local name noise near end
            data.extend(b"A" * rng.randint(16, 256))
        else:
            # Zero a random window
            if len(data) > 32:
                start = rng.randrange(0, len(data) - 16)
                end = min(len(data), start + rng.randint(4, 32))
                data[start:end] = b"\x00" * (end - start)

        out_path = out_dir / f"mutant_{seed}_{i:03d}{seed_path.suffix}"
        out_path.write_bytes(bytes(data))
        outputs.append(out_path)

    return outputs


def generate_xml_part_mutants(
    seed_path: Path,
    out_dir: Path,
    *,
    count: int = 5,
    seed: int = 0,
) -> list[Path]:
    """Mutate XML parts inside an OOXML package when the seed is a valid ZIP."""
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []

    try:
        parts, xml_names = _read_seed_parts(seed_path)
    except zipfile.BadZipFile:
        return generate_ooxml_mutants(seed_path, out_dir, count=count, seed=seed)
    if not xml_names:
        return generate_ooxml_mutants(seed_path, out_dir, count=count, seed=seed)

    for i in range(count):
        target = out_dir / f"xml_mutant_{seed}_{i:03d}{seed_path.suffix}"
        _write_xml_mutant(target, parts, xml_names[i % len(xml_names)], rng)
        outputs.append(target)

    return outputs


def _read_seed_parts(seed_path: Path) -> tuple[list[tuple[zipfile.ZipInfo, bytes]], list[str]]:
    """Read a bounded seed archive once and identify its XML mutation targets."""
    with zipfile.ZipFile(seed_path) as archive:
        validate_archive_safety(archive, allow_signed=True)
        parts = [(info, archive.read(info)) for info in archive.infolist()]
    return parts, [info.filename for info, _data in parts if info.filename.endswith(".xml")]


def _write_xml_mutant(
    target: Path,
    parts: list[tuple[zipfile.ZipInfo, bytes]],
    mutation_target: str,
    rng: random.Random,
) -> None:
    """Write one mutant while retaining every seed member and its metadata."""
    with zipfile.ZipFile(target, "w") as archive:
        for info, original in parts:
            data = _mutate_xml_part(original, rng) if info.filename == mutation_target else original
            archive.writestr(info, data)


def _mutate_xml_part(data: bytes, rng: random.Random) -> bytes:
    """Insert deterministic XML noise and optionally truncate the part."""
    if b">" in data:
        idx = data.find(b">")
        data = data[:idx] + b" fuzz='1'" + data[idx:]
    if rng.random() < 0.5 and len(data) > 10:
        data = data[:-5]
    return data
