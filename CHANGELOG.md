# Changelog

All notable changes to Dietrich are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[PEP 440](https://peps.python.org/pep-0440/) version identifiers.

Dietrich is pre-1.0 alpha software: commands, Python APIs, and output formats
can change between releases until a stable release is tagged.

## [Unreleased]

### Changed

- Redesigned the static `site/` demo around a "shear line" concept: the
  fixture-only Instrument Workbench now reads as a local document-locksmith's
  bench, with a locked-to-open readout gauge, a spec-sheet findings list, and a
  reworked screenshot tour. Behaviour, fixtures, the simulation/authorization
  notices, keyboard shortcuts, and the no-network/no-storage guarantees are
  unchanged; the work is markup and styling only (system fonts, no new assets).
- The experimental OOXML mutation-research generator moved out of the main
  `dietrich` command into its own `dietrich-research` console entry point (also
  runnable as `python -m dietrich.research`). The capability is unchanged; only
  its entry point moved, so the product CLI now contains document-assessment
  flags only.

### Added

- The public `dietrich` package now exports the assessment vocabulary returned
  by `inspect_document`/`inspect_workbook`: `ProtectionLayer`, `CapabilityCode`,
  `BlockerCode`, `Capability`, and `Blocker`. Callers can import and annotate
  with these instead of comparing attribute strings.

### Removed

- **Breaking (experimental):** removed the `--research-fuzz`, `--fuzz-count`, and
  `--fuzz-seed` flags from the `dietrich` command. There is no deprecation shim;
  old invocations now fail with an argparse error. Migrate:
  `dietrich IN --research-fuzz --fuzz-count N --fuzz-seed S` becomes
  `dietrich-research IN --count N --seed S`.
- Deleted the unused `dietrich.types` compatibility shim. Its names are the
  domain models already exported from the top-level `dietrich` package.

### Fixed

- Hardened untrusted Office and PDF parsing: Agile password work factors are
  capped, CFB parser failures remain fail-closed, raw PDF encryption dictionaries
  use bounded structural indexing, and malformed marked custom properties no
  longer enter a regular-expression recovery path.
- Legacy CFB mutation now validates exact FAT and MiniFAT chain lengths, rejects
  cycles and invalid sectors, and resolves streams by complete storage identity;
  ambiguous duplicate stream names are rejected.
- `AGENTS.md` is now tracked in version control instead of being excluded by a
  broad assistant-file ignore rule, so the repository guide ships with the
  source tree and matches CI.
- Documented toolchain commands (`AGENTS.md`, `README.md`, `CONTRIBUTING.md`)
  now match CI: the type-check and demo lanes require the `demo` dependency
  group, and linting covers `scripts` and `site/tests`.

## [0.4.0a5]

Alpha snapshot. See [docs/ALPHA.md](docs/ALPHA.md) for the current capability
and compatibility matrix, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for
component ownership and safety invariants.
