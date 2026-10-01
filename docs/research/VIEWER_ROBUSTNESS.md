# OOXML mutation research

The `dietrich-research` command (also runnable as `python -m dietrich.research`)
writes mutated copies of a ZIP OOXML file for local parser and viewer testing.
It is a separate lab utility, not part of the `dietrich` document command:

```bash
dietrich-research input.xlsx --count 20 --seed 7
```

The default destination is `research/fuzz/out`. Mutations mix selected XML
changes with bounded byte operations such as flips, truncation, inserted noise,
and zeroed windows.

The command does not launch viewers, classify crashes, minimize failing cases, or
target PDF and CFBF structures. Output may be malformed, so keep it in an
isolated test environment and never use confidential source documents.

When you report a result, include the Dietrich version, source fixture checksum,
seed, mutation count, platform, and application version. A mutation that one
viewer rejects is not by itself evidence of a security defect.
