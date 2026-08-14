"""Honest re-sign of OOXML packages with a user-supplied cert/key (never forges identity)."""

from __future__ import annotations

import base64
import hashlib
import zipfile
from html import escape as escape_html
from pathlib import Path

from dietrich.errors import InvalidDocumentError, MissingDependencyError, OutputExistsError
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.safety.zip_archive import validate_archive_safety


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
    x509, hashes, serialization, padding = _signing_primitives()

    package_path = Path(package_path)
    output_path = Path(output_path)
    if output_path.exists() and not overwrite:
        raise OutputExistsError(f"{output_path} already exists.")

    certificate = x509.load_pem_x509_certificate(Path(cert_pem).read_bytes())
    key = serialization.load_pem_private_key(Path(key_pem).read_bytes(), password=None)
    parts = _unsigned_package_parts(package_path)
    _add_signature_parts(parts, certificate, key, hashes, serialization, padding)
    with temporary_output_path(output_path) as temp_path:
        _write_signed_package(temp_path, parts)
        _verify_signed_package(temp_path)
        publish_output(temp_path, output_path, overwrite=overwrite)

    return output_path


def _signing_primitives():
    """Import optional cryptography primitives with Dietrich's dependency error."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as exc:
        raise MissingDependencyError(
            "Signature re-sign requires the cryptography package: "
            "pip install 'dietrich[sign]' (cryptography)."
        ) from exc
    return x509, hashes, serialization, padding


def _unsigned_package_parts(package_path: Path) -> dict[str, bytes]:
    """Read all package parts except a prior OOXML signature directory."""
    with zipfile.ZipFile(package_path) as archive:
        validate_archive_safety(archive, allow_signed=True)
        return {
            info.filename.replace("\\", "/"): archive.read(info)
            for info in archive.infolist()
            if not info.filename.lower().startswith("_xmlsignatures/")
        }


def _add_signature_parts(parts, certificate, key, hashes, serialization, padding) -> None:
    """Add a manifest signature plus its content-type and origin relationships."""
    manifest_xml = _build_manifest_xml(_part_references(parts))
    signed_info = _build_signed_info(manifest_xml)
    signature = key.sign(signed_info.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.b64encode(signature).decode("ascii")
    certificate_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode(
        "ascii"
    )
    parts["[Content_Types].xml"] = _ensure_signature_content_types(
        parts.get("[Content_Types].xml", b"<Types/>")
    )
    parts["_rels/.rels"] = _ensure_origin_rel(parts.get("_rels/.rels", b"<Relationships/>"))
    parts["_xmlsignatures/origin.sigs"] = _signature_origin_xml().encode("utf-8")
    parts["_xmlsignatures/sig1.xml"] = _build_signature_xml(
        signed_info, signature_b64, certificate_b64, manifest_xml
    ).encode("utf-8")


def _part_references(parts: dict[str, bytes]) -> list[tuple[str, str]]:
    """Hash every unsigned package part for the signature manifest."""
    return [
        (name, base64.b64encode(hashlib.sha256(parts[name]).digest()).decode("ascii"))
        for name in sorted(parts)
    ]


def _signature_origin_xml() -> str:
    """Build the OOXML relationship that points to the package signature XML."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/package/2006/relationships/'
        'digital-signature/signature" Target="sig1.xml"/>'
        "</Relationships>"
    )


def _write_signed_package(output_path: Path, parts: dict[str, bytes]) -> None:
    """Write a fully assembled signed package to a temporary output path."""
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)


def _verify_signed_package(path: Path) -> None:
    """Check the assembled signed ZIP before atomically publishing it."""
    try:
        with zipfile.ZipFile(path) as archive:
            validate_archive_safety(archive, allow_signed=True)
            failed_member = archive.testzip()
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(f"written signed package is not a valid ZIP: {exc}") from exc
    if failed_member is not None:
        raise InvalidDocumentError(
            f"written signed package failed ZIP verification at {failed_member}"
        )


def _build_manifest_xml(references: list[tuple[str, str]]) -> str:
    """Internal helper: _build_manifest_xml."""
    refs = []
    for name, digest in references:
        # Package-relative URI
        uri = "/" + name.lstrip("/")
        refs.append(
            f'<Reference URI="{escape_html(uri, quote=False)}">'
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
