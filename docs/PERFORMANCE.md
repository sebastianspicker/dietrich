# Local performance measurements

These numbers come from one machine and one synthetic workload. They document
what changed and how to reproduce it; they are not a general speedup claim.

## OOXML rewriting

The OOXML benchmark uses seed 73521, one warmup, and five measured runs on the
same macOS 26.6.2 arm64 machine and Python 3.12.12 environment. It creates one
workbook main part and 64 random 32 KiB members with ZIP deflate compression.
Fixture creation is outside the timed region, and each run writes a new target.
The baseline was measured before this change; the updated run uses
`scripts/benchmark_ooxml.py`.

| Metric | Baseline median (range) | Updated median (range) |
| --- | --- | --- |
| Elapsed milliseconds | 47.263 (46.457–48.537) | 40.853 (40.684–41.123) |
| ZIP member read calls | 66.000 (66.000–66.000) | 66.000 (66.000–66.000) |
| ZIP metadata member checks | 325.000 (325.000–325.000) | 195.000 (195.000–195.000) |
| Peak traced Python KiB | 425.326 (424.990–1161.914) | 426.881 (420.373–427.127) |

Metadata checks fell from five scans to three: one checked private source, plus
fresh writer and publication validation. Both complete CRC passes remain. Member
read calls count `ZipFile.read`, not low-level bytes or CRC stream reads, and
`tracemalloc` measures Python allocations, not total RSS or native library
memory. Elapsed times are local observations from this synthetic workload with
no claimed general speedup; the source-check reduction is directly counted.

Reproduce the updated workload with:

```bash
uv run python scripts/benchmark_ooxml.py
```

## Native PDF fallback

A second benchmark uses a 4,194,633-byte synthetic PDF with revision-3 Standard
handler fields and seed-73521 padding. Both versions run in the same interpreter
with one warmup and five measured runs each. The baseline module comes from
`0a0aee41e862:src/dietrich/pdf/hash.py`, which was clean before implementation.
The `pikepdf.open` call deliberately raises `PasswordError`, which isolates the
native fallback instead of measuring decryption or PDF parser performance.

| Metric | Baseline median (range) | Updated median (range) |
| --- | --- | --- |
| Elapsed milliseconds | 6.289 (6.067–6.843) | 5.633 (5.610–5.705) |
| Bounded full-file reads | 2.000 (2.000–2.000) | 1.000 (1.000–1.000) |
| Peak traced Python MiB | 132.016 (132.016–132.016) | 128.014 (128.014–128.014) |

The fallback now reuses the buffer already read by the exporter. Peak traced
allocations include the bounded reader's temporary allocation for its maximum
read size; they are not the file size or resident memory. These measurements do
not establish a recovery-throughput improvement.

```bash
git show 0a0aee41e862:src/dietrich/pdf/hash.py > /tmp/dietrich-pdf-hash-before.py
uv run python scripts/benchmark_pdf.py --baseline /tmp/dietrich-pdf-hash-before.py
```

Legacy rewriting now releases original stream buffers before the full-file patch
allocation. No measured legacy peak-RSS improvement is claimed.
