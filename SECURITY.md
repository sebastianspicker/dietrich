# Security policy

## Supported use

Dietrich is intended only for documents that the operator owns or is authorized
to modify. It removes supported document flags and performs local password
recovery. It does not acquire or bypass Microsoft Purview, Azure RMS, or other
server-managed rights licenses.

## Report a vulnerability

Please do not publish exploit details, confidential documents, passwords, hashes,
certificates, or private keys in a public issue. Use the repository's
[private vulnerability reporting page](https://github.com/sebastianspicker/dietrich/security/advisories/new)
when it is available. If it is not, open a public issue that only asks for a
private contact channel and contains no sensitive technical detail.

Include the Dietrich version, operating system, affected format, impact, and a
minimal synthetic reproduction.

## Data and output handling

Dietrich processes local paths and defines no remote service or database. The
optional graphical launcher starts a loopback HTTP session on `127.0.0.1`. Its
random session token authorizes local file browsing and document operations, so
keep the launch URL private and never expose or proxy the port to a network.
Requests require the session header and matching Host and Origin checks. The
process serves only its bundled assets, has no general file-download endpoint,
and omits passwords from operation results. Stop the launcher when you are done;
closing the browser tab does not stop an active operation.

Operations can create decrypted documents, unsigned copies, password hashes, and
malformed research mutants. Treat these outputs as sensitive and restrict access
to them.

Work on a copy of the source. The default output is a new sibling path. `--force`
allows replacement of an existing target and should be used only after that path
has been checked. Successful publication uses a private mode-`0600` temporary
file and one atomic replace.

## Input boundaries

| Input | Limit |
| --- | --- |
| ZIP members | 10,000 |
| Per-member size | 64 MiB |
| Total uncompressed size | 512 MiB |
| Compression ratio | 100:1 |

Duplicate and encrypted ZIP entries are rejected. Signed OOXML is rejected unless
signature stripping is explicit; stripping creates an unsigned copy and removes
authenticity evidence. Experimental re-signing neither implements complete
Microsoft Office signature compatibility nor establishes certificate trust.

Legacy Office editing is limited to recognized equal-length record patches. IRM
detection fails closed. Unsupported, malformed, or ambiguous structures are
rejected rather than processed with relaxed checks.

## Dependencies and external tools

Optional format support uses `msoffcrypto-tool`, `pikepdf`, `olefile`,
`cryptography`, and `textual`. Review dependency updates and install from trusted
package sources. `hashcat` and the optional `pdf2john` fallback are separate
local executables; Dietrich does not install or operate a remote recovery
service.
