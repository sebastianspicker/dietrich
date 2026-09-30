# OOXML signatures

## Default: reject signed packages

Dietrich detects OOXML signature parts before modification and rejects signed
packages. Any rewrite would invalidate the existing signature, so there is no
silent safe path.

## Stripping

`--strip-signatures` explicitly creates an unsigned copy. It removes signature
parts, signature relationships, and related content-type declarations before the
normal OOXML rewrite. This destroys authenticity evidence, so record the decision
in your workflow.

## Experimental re-signing

`--resign-cert CERT.pem --resign-key KEY.pem` adds OOXML origin and signature
parts after the ZIP output is written. The implementation:

- accepts a PEM certificate and an unencrypted RSA private key;
- finalizes the signature content types and discovery relationships before
  digesting every package part with SHA-256;
- canonicalizes the package `Object` and `SignedInfo` with inclusive C14N
  1.0 and signs with RSA PKCS#1 v1.5;
- writes an empty `_xmlsignatures/origin.sigs`, its relationship part, and
  `_xmlsignatures/sig1.xml`;
- reopens the candidate and verifies the RSA signature, package-object digest,
  every manifest digest, ZIP structure, and CRC before it can be published.

This is a W3C XML-DSig-valid experimental subset, not a complete OPC signature
implementation. It does not implement content-type-bound OPC reference URIs,
the OPC relationship transform, package signature properties or timestamps,
revocation checking, certificate-chain validation, hardware-backed keys, or
application-specific trust behavior. The tests independently verify the XML
signature and final package bytes; they do not establish acceptance or trust in
Microsoft Office.

Re-signing applies only to ZIP OOXML output, not to PDF or legacy binary Office
files.
