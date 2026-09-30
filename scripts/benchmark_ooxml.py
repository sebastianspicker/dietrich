"""Fixed synthetic OOXML benchmark: seed 73521, one warmup, five measured runs."""

import json
import random
import statistics
import tempfile
import time
import tracemalloc
import zipfile
from pathlib import Path
from unittest.mock import patch

from dietrich import unlock_document
from dietrich.safety import zip_archive


def main():
    rng = random.Random(73521)
    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder) / "source.xlsx"
        with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("xl/workbook.xml", "<workbook/>")
            for index in range(64):
                archive.writestr(f"custom/data{index}.bin", rng.randbytes(32768))
        original_read = zipfile.ZipFile.read
        original_check = zip_archive._validate_member_limits
        rows = []
        for index in range(6):
            counts = {"member_reads": 0, "member_checks": 0}

            def read(self, *args, counts=counts, **kwargs):
                counts["member_reads"] += 1
                return original_read(self, *args, **kwargs)

            def check(info, counts=counts):
                counts["member_checks"] += 1
                return original_check(info)

            tracemalloc.start()
            start = time.perf_counter()
            with (
                patch.object(zipfile.ZipFile, "read", read),
                patch.object(zip_archive, "_validate_member_limits", check),
            ):
                unlock_document(source, Path(folder) / f"output{index}.xlsx")
            elapsed = time.perf_counter() - start
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            if index:
                rows.append({"elapsed_seconds": elapsed, "peak_python_bytes": peak, **counts})
        print(
            json.dumps(
                {
                    "seed": 73521,
                    "warmup": 1,
                    "runs": rows,
                    "summary": {
                        key: {
                            "median": statistics.median(row[key] for row in rows),
                            "range": [min(row[key] for row in rows), max(row[key] for row in rows)],
                        }
                        for key in rows[0]
                    },
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
