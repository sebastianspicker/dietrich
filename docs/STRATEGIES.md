# Processing strategy

## Classification and routing

`dietrich.crypto.detect.classify_path` uses magic bytes and suffix information to
classify PDF, CFBF/OLE, ZIP OOXML, and unknown input. `dietrich.dispatch` then
applies this order:

1. Detect and reject IRM-protected input.
2. Route encrypted Office input through password recovery and decryption.
3. Route PDF input through the PDF handler.
4. Route ZIP OOXML input through archive validation and XML rewriting.
5. Route legacy Office input through equal-length CFB stream patching.

An encrypted Office payload is decrypted to a temporary path. If the payload is
OOXML, normal soft-protection processing follows. A non-ZIP payload is published
unchanged after decryption with a warning.

## OOXML

OOXML processing validates archive limits, rejects signed packages unless
stripping is explicit, rewrites only recognized XML parts, preserves ZIP entry
metadata and compression where possible, reopens the output for verification,
and then publishes it.

The format modules own their XML elements:

- `ooxml/excel.py`: worksheets, chartsheets, and workbook settings
- `ooxml/word.py`: document and write protection
- `ooxml/powerpoint.py`: modification verifier
- `ooxml/props.py`: package security properties
- `ooxml/vba.py`: optional VBA project verifier fields

## Password and hash paths

`crypto/attack.py` creates bounded password candidates. `crypto/ooxml_crypto.py`
uses `msoffcrypto-tool` for Office password verification and decryption.
`crypto/hash_export.py` and `crypto/pdf_hash.py` produce offline hash formats.
`crypto/hashcat_runner.py` invokes a separately installed local hashcat process.

`--soft-only` rejects encrypted input instead of attempting password recovery.

## PDF

`pdf/permissions.py` opens the input with `pikepdf` and saves without encryption.
User-password input is required when the file cannot be opened with an empty
password. Native hash extraction is limited to supported Standard security
handler revisions and field combinations.

## Legacy Office

The legacy path reads CFB streams through `olefile`, recognizes selected BIFF,
Word FIB, and PowerPoint records, and applies patches that preserve stream length.
It is intentionally narrower than a complete CFBF rewrite.

## Signatures

Signed OOXML fails closed. `--strip-signatures` removes signature parts,
relationships, and content-type declarations. Experimental re-signing creates
origin and signature parts using a supplied certificate and unencrypted RSA
private key. It is limited to ZIP OOXML and does not implement the complete
Office signing model.

## Publication

`safety/publish.py` publishes completed temporary outputs. Normal mode uses an
exclusive path operation and refuses collisions. `--force` uses replacement.
Format processing must complete before publication is called.
