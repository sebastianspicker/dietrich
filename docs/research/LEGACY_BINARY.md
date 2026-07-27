# Legacy binary Office support

Legacy `.xls`, `.doc`, and `.ppt` files use CFBF/OLE compound storage rather than
OOXML ZIP packages. Dietrich uses `olefile` to read streams and applies only
recognized equal-length patches.

## Implemented paths

- Excel BIFF workbook protection records
- Word FIB protection fields
- PowerPoint protection-related records recognized by the parser

The writer preserves the compound-file layout by requiring replacement bytes to
have the same length as the original stream. After writing, Dietrich reopens the
output for validation.

## Limits

This path is not a complete CFBF writer and does not repair damaged compound
files. Unknown protectors, producer-specific extensions, encryption, and record
layouts outside the implemented patterns may remain unchanged. When no recognized
record is found, the command emits a warning rather than claiming a modification.

Tests use public non-confidential fixtures under `tests/fixtures/`.
