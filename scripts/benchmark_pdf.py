"""Compare native PDF fallback buffer use with an optional saved baseline module."""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from unittest.mock import patch

import pikepdf

from dietrich.pdf import hash as current


def measure(module, path: Path):
    original = module.read_file_limited
    rows = []
    for index in range(6):
        counts = {"bounded_reads": 0}

        def read(*args, counts=counts):
            counts["bounded_reads"] += 1
            return original(*args)

        tracemalloc.start()
        start = time.perf_counter()
        with (
            patch.object(module, "read_file_limited", read),
            patch.object(pikepdf, "open", side_effect=pikepdf.PasswordError("synthetic fallback")),
        ):
            result = module.export_pdf_hash(path)
            assert result.startswith("$pdf$2*3*128*")
        elapsed = time.perf_counter() - start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        if index:
            rows.append({"elapsed_seconds": elapsed, "peak_python_bytes": peak, **counts})
    return {
        "runs": rows,
        "summary": {
            key: {
                "median": statistics.median(row[key] for row in rows),
                "range": [min(row[key] for row in rows), max(row[key] for row in rows)],
            }
            for key in rows[0]
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    modules = {"updated": current}
    if args.baseline:
        spec = importlib.util.spec_from_file_location("pdf_baseline", args.baseline)
        assert spec is not None and spec.loader is not None
        baseline = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = baseline
        spec.loader.exec_module(baseline)
        modules = {"baseline": baseline, **modules}
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "synthetic.pdf"
        rng = random.Random(73521)
        raw = b"%PDF-1.7\n%" + rng.randbytes(2 * 1024 * 1024).hex().encode() + b"\n"
        raw += (
            f"1 0 obj << /Filter /Standard /V 2 /R 3 /Length 128 /P -4 "
            f"/O <{'11' * 32}> /U <{'22' * 32}> >> endobj\n"
            f"trailer << /Encrypt 1 0 R /ID [<{'ab' * 16}> <{'ab' * 16}>] >>\n"
            "%%EOF\n"
        ).encode()
        source.write_bytes(raw)
        print(
            json.dumps(
                {
                    "seed": 73521,
                    "warmup": 1,
                    "input_bytes": len(raw),
                    **{name: measure(module, source) for name, module in modules.items()},
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
