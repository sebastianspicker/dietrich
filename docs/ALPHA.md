# Capability and compatibility status

Dietrich 0.4.0a4 is an alpha release. This document records implemented behavior,
not a compatibility guarantee for every document producer or viewer.

## Format matrix

| Format or protection | Status | Notes |
|---|---|---|
| Excel OOXML worksheet and chartsheet protection | Supported | Removes recognized protection elements |
| Excel OOXML workbook protection | Supported | Can be retained with `--keep-document-protection` |
| Word OOXML document and write protection | Supported | Removes recognized settings elements |
| PowerPoint OOXML modify verifier | Supported | Can be retained with `--keep-modify-verifier` |
| OOXML package properties | Supported | Clears recognized `DocSecurity` and `MarkAsFinal` values |
| Encrypted Office Agile and Standard formats | Optional | Requires `msoffcrypto-tool` and a recovered password |
| Legacy `.xls`, `.doc`, `.ppt` | Limited | Known equal-length record patches only |
| PDF encryption and permissions | Optional | Requires `pikepdf` |
| Office password hash export | Optional | Requires `msoffcrypto-tool` |
| PDF password hash export | Limited | Standard handler revisions 2 through 6 |
| Signed OOXML stripping | Supported | Explicit opt-in; output is unsigned |
| OOXML re-signing | Experimental | RSA/SHA-256 subset; no complete Office compatibility claim |
| VBA project verifier clearing | Experimental | Recognized CMG, DPB, and GC fields only |
| Microsoft Purview, Azure RMS, and IRM | Detection only | Processing is rejected |
| OOXML mutation research | Experimental | Local byte and XML mutations; no viewer automation |

## Password recovery

Dietrich can test an explicit password, stream a wordlist, expand a mask, or
enumerate a bounded character set. Mask tokens are `?d`, `?l`, `?u`, `?a`, `?s`,
and `??`. `--brute` defaults to decimal digits with a maximum length of 4 unless
other limits are provided.

The default candidate ceiling is 5,000,000. Multiple workers use processes for
verification but may materialize the candidate set in memory. Large search spaces
should use external hashcat orchestration instead.

## Output behavior

Unlock commands write a separate sibling file by default. Existing targets are
rejected unless `--force` is supplied. OOXML input is validated before rewriting,
the written ZIP is reopened for verification, and publication occurs only after
the temporary output succeeds.

ZIP safety limits are 10,000 members, 64 MiB per member, 512 MiB total
uncompressed content, and a 100:1 compression ratio. Duplicate and encrypted ZIP
entries are rejected.

## Compatibility boundaries

Tests use synthetic and public fixtures. They cover the format routes, CLI,
Python API, and terminal state mapping. They do not cover all Office producers,
all PDF security handlers, Microsoft Office trust dialogs, hardware-backed keys,
or third-party viewers.
