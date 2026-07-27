# Security policy

## Supported use

Dietrich is intended for documents that the operator owns or is authorized to
modify. It removes document flags and performs local password recovery. It does
not bypass Microsoft Purview, Azure RMS, or other server-managed rights systems.

## Reporting a vulnerability

Do not publish exploit details in a GitHub issue. Use the repository's private
security-reporting channel when available, or contact the maintainer identified
in `pyproject.toml` through the repository host.

Include the Dietrich version, operating system, minimal reproduction, affected
format, and impact. Do not attach confidential documents, passwords, private
keys, or exported hashes.

## Data handling

Dietrich processes local paths and does not define a network service. Operations
can create decrypted documents, unsigned copies, password hashes, and research
mutants. Treat those outputs as sensitive and restrict access to them.

Use a copy of the source document. The default output is a new sibling path.
`--force` permits replacement of an existing output and should be used only after
the target path has been checked.

## Archive and format boundaries

OOXML input is rejected when it contains duplicate or encrypted ZIP entries,
more than 10,000 members, a member over 64 MiB, more than 512 MiB total
uncompressed content, or a compression ratio over 100:1.

Signed OOXML input is rejected unless signature stripping is explicit. Stripping
creates an unsigned copy and removes authenticity evidence. Experimental
re-signing does not provide complete Microsoft Office signature compatibility or
establish certificate trust.

Legacy Office editing is limited to recognized equal-length record patches. IRM
detection fails closed.

## Dependencies

Optional format support uses `msoffcrypto-tool`, `pikepdf`, `olefile`,
`cryptography`, `textual`, and `rich`. Review dependency updates and install from
trusted package sources. `hashcat` is a separate executable and is not installed
by Dietrich.
