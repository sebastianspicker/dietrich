# Capability and compatibility status

Dietrich 0.4.0a5 is an alpha release. This page records what is actually
implemented; it is not a compatibility guarantee for every document producer or
viewer.

The `dietrich-gui` launcher adds a local graphical adapter over the same
operations. It does not expand format support or viewer compatibility. Its
interaction, loopback-session, and process-lifetime boundaries are documented in
[GUI.md](GUI.md).

## Format matrix

| Format or protection | Status | Notes |
|---|---|---|
| Excel OOXML worksheet and chartsheet protection | Supported | Removes recognized protection elements |
| Excel OOXML workbook protection | Supported | Can be retained with `--worksheets-only` |
| Word OOXML document and write protection | Supported | Removes recognized settings elements |
| PowerPoint OOXML modify verifier | Supported | Can be retained with `--keep-modify-verifier` |
| OOXML package properties | Supported | Clears recognized `DocSecurity` and parsed `MarkAsFinal` values; malformed marked custom XML is rejected |
| Encrypted Office Agile and Standard formats | Optional | Requires `msoffcrypto-tool` and a recovered password; Agile `spinCount` is capped at 1,000,000 |
| Legacy `.xls`, `.doc` | Limited | Verified BIFF8 record and Word FIB field patches only |
| Legacy `.ppt` | Inspection only | Mutation is rejected until a verified record parser exists |
| PDF encryption and permissions | Optional | Requires `pikepdf` |
| Office password hash export | Optional | Requires `msoffcrypto-tool` |
| PDF password hash export | Limited | Standard handler revisions 2 through 6 |
| Signed OOXML stripping | Supported | Explicit opt-in; output is unsigned |
| OOXML re-signing | Experimental | W3C XML-DSig-valid RSA/SHA-256 subset; no complete OPC or Office compatibility claim |
| VBA project verifier clearing | Experimental | Recognized CMG, DPB, and GC fields only |
| Microsoft Purview, Azure RMS, and IRM | Detection only | Processing is rejected |
| OOXML mutation research | Experimental | Separate `dietrich-research` command; local byte and XML mutations; no viewer automation |

## Password recovery

Dietrich can test an explicit password, stream a wordlist, expand a mask, or
enumerate a bounded character set. Mask tokens are `?d`, `?l`, `?u`, `?a`, `?s`,
and `??`. `--brute` defaults to decimal digits with a maximum length of 4 unless
other limits are provided.

The default candidate ceiling is 5,000,000. Multiple workers verify through a
spawn-based process window of at most twice the worker count. Workers are stopped
and reaped on success, failure, or cancellation. Use external hashcat
orchestration for larger search spaces.

## Output behavior

Unlock commands write a separate sibling file by default. Existing targets are
rejected unless `--force` is supplied. OOXML input is validated before rewriting,
every written candidate is reopened for verification, and one private
mode-`0600` file is published only after all optional post-processing succeeds.

ZIP safety limits are 10,000 members, 64 MiB per member, 512 MiB total
uncompressed content, and a 100:1 compression ratio. Duplicate and encrypted ZIP
entries are rejected.

CFB safety limits are 512 MiB per input, 10,000 streams, 128 MiB per stream,
and 256 MiB aggregate declared stream data. Legacy mutation additionally
requires exact storage-path identity and an acyclic allocation chain whose
length matches the declared stream size. Raw PDF hash fallback rejects more
than 64 nested dictionaries.

## Compatibility boundaries

The direct suite uses small synthetic byte streams to cover parsing and output
safety. It does not cover every Office producer, PDF security handler, Microsoft
Office trust dialog, hardware-backed key, or third-party viewer.

## Cancellation and local verification

Python callers can pass `control=OperationControl()` to any of the five public
functions, and the TUI exposes Cancel and phase status. Accepted cancellation
leaves the destination untouched. Once publication begins, cancellation is
declined and quit waits for the operation and cleanup. Native calls finish their
current call before cancellation takes effect.

Controlled decryption tests exercise XLSX, DOCX, and PPTX orchestration and
preserve encrypted-input provenance; they differ from the real encrypted PDF
roundtrips in the suite. Synthetic signing tests independently verify the RSA
signature, package-object digest, and final part digests without establishing
OPC completeness, Microsoft Office trust, or interoperability. Windows process
cleanup is tested through its direct-child fallback. Live Windows, hashcat, and
Office-viewer behavior need separate environment verification.
