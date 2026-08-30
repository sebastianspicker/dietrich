# Processing strategy

## Assessment

`application.assess.assess_document` is the single inspection path. It identifies PDF, OOXML,
encrypted Office, legacy binary Office, or unknown input; runs the IRM gate; and returns the
stable `DocumentInspection` projection plus typed capabilities and blockers. CLI and TUI
presentation consume this result instead of repeating probes or parsing note text. Every
application use case enforces blockers before it routes to transformation or hash-export code.

## Make-editable transaction

`application.make_editable.make_editable_copy` owns the complete output-producing use case:

1. create a private transaction workspace and snapshot the source once;
2. assess the snapshot and reject rights-managed or unsupported input;
3. resolve an open password and decrypt when necessary;
4. ask one format module to write an unpublished candidate;
5. require the format writer to validate its candidate;
6. optionally re-sign and validate a second unpublished OOXML candidate;
7. validate the final candidate again by concrete artifact kind;
8. copy it into an adjacent mode-`0600` file and publish exactly once.

Any failure before step 8 leaves an absent target absent and an existing target unchanged.

## Format ownership

- `ooxml/`: archive inspection, XML transforms, signatures, Office encryption, and candidate
  writing.
- `pdf/`: PDF inspection, password/hash handling, and unrestricted candidate writing.
- `legacy/`: verified equal-length BIFF/FIB transforms and fail-closed PowerPoint inspection.
- `crypto/`: password candidate generation and controlled local hashcat execution.

Candidate writers never publish or decide overwrite policy. OOXML validation rejects unsafe
names, duplicate aliases, encrypted entries, excessive expansion, ambiguous or missing defining
main parts, and signed packages unless stripping is explicit. CFB processing enforces input,
entry, per-stream, and aggregate limits. BIFF mutation requires supported BOF/EOF-framed
substreams; arbitrary marker scanning is forbidden.

## External tools

Hashcat and pdf2john are local optional executables. They run without a shell, in private working
directories, with a reduced environment, closed stdin, bounded captured output, and fixed
Dietrich-owned output paths. User hashcat arguments cannot override those paths or modes.
