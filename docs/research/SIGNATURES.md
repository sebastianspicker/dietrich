# OOXML signatures

## Default behavior

Dietrich detects OOXML signature parts before modification and rejects signed
packages. Any document rewrite would invalidate the existing signature.

## Signature stripping

`--strip-signatures` explicitly creates an unsigned copy. It removes signature
parts, signature relationships, and related content-type declarations before the
normal OOXML rewrite. This removes authenticity evidence and should be recorded
in the operator's workflow.

## Experimental re-signing

`--resign-cert CERT.pem --resign-key KEY.pem` adds OOXML origin and signature
parts after a ZIP OOXML output has been written. The implementation:

- accepts a PEM certificate and an unencrypted RSA private key;
- digests selected package parts with SHA-256;
- signs with RSA PKCS#1 v1.5;
- writes `_xmlsignatures/origin.sigs` and `_xmlsignatures/sig1.xml`.

This is a limited ECMA-376-style subset. It does not implement the complete
Microsoft Office transform model, timestamping, revocation checking, certificate
chain validation, hardware-backed keys, or application-specific trust behavior.
The repository tests verify package structure and cryptographic output, not
acceptance by Microsoft Office.

Re-signing applies only to ZIP OOXML output. It does not apply to PDF or legacy
binary Office files.
