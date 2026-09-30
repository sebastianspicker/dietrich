# Legacy binary Office support

Legacy `.xls`, `.doc`, and `.ppt` files store their data in CFBF/OLE compound
storage rather than OOXML ZIP packages. Dietrich reads those streams with
`olefile` under strict bounds and applies only structurally verified,
equal-length patches. It is not a general compound-file editor.

## What works

- Excel BIFF8 workbook protection records inside complete BOF/EOF substreams.
- Word FIB protection fields.
- PowerPoint container inspection. Mutation is intentionally unavailable.

The writer keeps the compound-file layout intact by requiring replacement bytes
to match the original stream length. After writing, Dietrich reopens the output
and validates it.

## What does not

This path is not a complete CFBF writer and cannot repair damaged compound
files. Malformed BIFF walks, unrecognized Word FIB headers, PowerPoint mutation,
unknown protectors, producer-specific extensions, encryption, and record layouts
outside the implemented patterns either fail explicitly or are left unchanged.
Dietrich never scans arbitrary content for protection-looking byte strings.

The test suite builds only small synthetic byte streams; no real legacy
documents are tracked.
