# OOXML mutation research

The research command creates mutated copies of a ZIP OOXML input for local parser
and viewer testing:

```bash
dietrich input.xlsx --research-fuzz --fuzz-count 20 --fuzz-seed 7
```

The default destination is `research/fuzz/out`. Mutations include selected XML
changes and bounded byte operations such as flips, truncation, inserted noise,
and zeroed windows.

This command does not launch viewers, classify crashes, minimize failing cases,
or target PDF and CFBF structures. Outputs may be malformed and must remain in an
isolated test environment. Do not use confidential source documents.

Record the Dietrich version, source fixture checksum, seed, mutation count,
platform, and application version when reporting a result. A mutation that one
viewer rejects is not by itself evidence of a security defect.
