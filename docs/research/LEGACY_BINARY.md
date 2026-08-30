# Legacy binary Office support

Legacy `.xls`, `.doc`, and `.ppt` files use CFBF/OLE compound storage rather than
OOXML ZIP packages. Dietrich uses `olefile` for bounded stream access and applies
only structurally verified equal-length patches.

## Implemented paths

- Excel BIFF8 workbook protection records inside complete BOF/EOF substreams
- Word FIB protection fields
- PowerPoint container inspection; mutation is deliberately unavailable

The writer preserves the compound-file layout by requiring replacement bytes to
have the same length as the original stream. After writing, Dietrich reopens the
output for validation.

## Limits

This path is not a complete CFBF writer and does not repair damaged compound
files. Malformed BIFF walks, unrecognized Word FIB headers, PowerPoint mutation,
unknown protectors, producer-specific extensions, encryption, and record layouts
outside the implemented patterns fail explicitly or remain unchanged. Dietrich
does not scan arbitrary content for protection-looking byte strings.

The direct suite builds only small synthetic byte streams; no legacy documents
are tracked for testing.
