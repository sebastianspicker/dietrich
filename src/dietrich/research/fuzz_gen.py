"""Experimental local-lab OOXML mutant generators (not a product unlock path).

The seeded generator intentionally makes a fuzz case reproducible. It is never
used for passwords, keys, or any other security-sensitive value.
"""

from __future__ import annotations

import random
import zipfile
from pathlib import Path


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
        with zipfile.ZipFile(seed_path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".xml")]
            if not names:
                return generate_ooxml_mutants(seed_path, out_dir, count=count, seed=seed)
            for i in range(count):
                target = out_dir / f"xml_mutant_{seed}_{i:03d}{seed_path.suffix}"
                with zipfile.ZipFile(target, "w") as out:
                    for info in zf.infolist():
                        data = zf.read(info)
                        if info.filename == names[i % len(names)]:
                            data = _mutate_xml_part(data, rng)
                        out.writestr(info, data)
                outputs.append(target)
    except zipfile.BadZipFile:
        return generate_ooxml_mutants(seed_path, out_dir, count=count, seed=seed)

    return outputs


def _mutate_xml_part(data: bytes, rng: random.Random) -> bytes:
    """Insert deterministic XML noise and optionally truncate the part."""
    if b">" in data:
        idx = data.find(b">")
        data = data[:idx] + b" fuzz='1'" + data[idx:]
    if rng.random() < 0.5 and len(data) > 10:
        data = data[:-5]
    return data
