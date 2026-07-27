"""Honest re-sign of OOXML packages with a user-supplied cert/key (never forges identity)."""

from __future__ import annotations

import base64
import hashlib
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from dietrich.errors import MissingDependencyError


def resign_ooxml_package(
    package_path: Path,
    output_path: Path,
    *,
    cert_pem: Path,
    key_pem: Path,
    overwrite: bool = False,
) -> Path:
    """Re-sign an OOXML package using cert/key PEM files.

    Builds `_xmlsignatures/origin.sigs` + `sig1.xml` with XML-DSig enveloping
    a simple manifest of part digests (ECMA-376 style subset).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise MissingDependencyError(
            "Signature re-sign requires the cryptography package: "
            "pip install 'dietrich[sign]' (cryptography)."
        ) from exc

    package_path = Path(package_path)
    output_path = Path(output_path)
    if output_path.exists() and not overwrite:
        from dietrich.errors import OutputExistsError

        raise OutputExistsError(f"{output_path} already exists.")

    cert = x509.load_pem_x509_certificate(Path(cert_pem).read_bytes())
    key = serialization.load_pem_private_key(Path(key_pem).read_bytes(), password=None)

    # Read all parts except old signatures
    parts: dict[str, bytes] = {}
    with zipfile.ZipFile(package_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.lower().startswith("_xmlsignatures/"):
                continue
            parts[name] = zf.read(info)

    # Manifest: SHA-256 of each part (excluding signature parts we add)
    references: list[tuple[str, str]] = []
    for name in sorted(parts):
        digest = base64.b64encode(hashlib.sha256(parts[name]).digest()).decode("ascii")
        references.append((name, digest))

    manifest_xml = _build_manifest_xml(references)
    # SignedInfo over manifest
    signed_info = _build_signed_info(manifest_xml)
    signature_value = key.sign(
        signed_info.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = base64.b64encode(signature_value).decode("ascii")
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")

    sig_xml = _build_signature_xml(signed_info, sig_b64, cert_b64, manifest_xml)
    origin = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/package/2006/relationships/'
        'digital-signature/signature" '
        'Target="sig1.xml"/>'
        "</Relationships>"
    )

    # Content types + root rels updates
    ct = parts.get("[Content_Types].xml", b"<Types/>")
    ct = _ensure_signature_content_types(ct)
    parts["[Content_Types].xml"] = ct

    root_rels = parts.get("_rels/.rels", b"<Relationships/>")
    root_rels = _ensure_origin_rel(root_rels)
    parts["_rels/.rels"] = root_rels

    parts["_xmlsignatures/origin.sigs"] = origin.encode("utf-8")
    parts["_xmlsignatures/sig1.xml"] = sig_xml.encode("utf-8")

    if output_path.exists():
        output_path.unlink()
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts.items():
            zf.writestr(name, data)

    return output_path


def _build_manifest_xml(references: list[tuple[str, str]]) -> str:
    """Internal helper: _build_manifest_xml."""
    refs = []
    for name, digest in references:
        # Package-relative URI
        uri = "/" + name.lstrip("/")
        refs.append(
            f'<Reference URI="{escape(uri)}">'
            f"<DigestMethod Algorithm="
            f'"http://www.w3.org/2001/04/xmlenc#sha256"/>'
            f"<DigestValue>{digest}</DigestValue>"
            f"</Reference>"
        )
    return '<Manifest xmlns="http://www.w3.org/2000/09/xmldsig#">' + "".join(refs) + "</Manifest>"


def _build_signed_info(manifest_xml: str) -> str:
    # Simplified SignedInfo - Office may require more transforms; this is honest user re-sign.
    """Internal helper: _build_signed_info."""
    digest = hashlib.sha256(manifest_xml.encode("utf-8")).digest()
    manifest_digest = base64.b64encode(digest).decode("ascii")
    return (
        '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        '<Reference URI="#idPackageObject">'
        '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        f"<DigestValue>{manifest_digest}</DigestValue>"
        "</Reference>"
        "</SignedInfo>"
    )


def _build_signature_xml(
    signed_info: str,
    signature_value_b64: str,
    cert_b64: str,
    manifest_xml: str,
) -> str:
    """Internal helper: _build_signature_xml."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="idPackageSignature">'
        f"{signed_info}"
        f"<SignatureValue>{signature_value_b64}</SignatureValue>"
        "<KeyInfo><X509Data>"
        f"<X509Certificate>{cert_b64}</X509Certificate>"
        "</X509Data></KeyInfo>"
        f'<Object Id="idPackageObject">{manifest_xml}</Object>'
        "</Signature>"
    )


def _ensure_signature_content_types(ct: bytes) -> bytes:
    """Internal helper: _ensure_signature_content_types."""
    text = ct.decode("utf-8", errors="replace")
    if "_xmlsignatures" in text:
        return ct
    override = (
        '<Override PartName="/_xmlsignatures/origin.sigs" '
        'ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/>'
        '<Override PartName="/_xmlsignatures/sig1.xml" '
        'ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/>'
    )
    if "</Types>" in text:
        text = text.replace("</Types>", override + "</Types>")
    else:
        text = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            f"{override}</Types>"
        )
    return text.encode("utf-8")


def _ensure_origin_rel(rels: bytes) -> bytes:
    """Internal helper: _ensure_origin_rel."""
    text = rels.decode("utf-8", errors="replace")
    if "digital-signature/origin" in text:
        return rels
    rel = (
        '<Relationship Id="rIdSig" '
        'Type="http://schemas.openxmlformats.org/package/2006/relationships/'
        'digital-signature/origin" '
        'Target="_xmlsignatures/origin.sigs"/>'
    )
    if "</Relationships>" in text:
        text = text.replace("</Relationships>", rel + "</Relationships>")
    else:
        text = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{rel}</Relationships>"
        )
    return text.encode("utf-8")
