"""Write and validate experimental XML-DSig OOXML candidates."""

from __future__ import annotations

import base64
import hashlib
import hmac
import zipfile
from pathlib import Path
from urllib.parse import quote, unquote

from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.domain.models import DocumentFormat, RemovalCounts
from dietrich.errors import InvalidDocumentError, MissingDependencyError
from dietrich.operation import checkpoint
from dietrich.safety.zip_archive import validate_archive_safety, verify_archive_crc

_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_CONTENT_TYPES_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_RELATIONSHIPS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_C14N_ALGORITHM = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_RSA_SHA256_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256"
_OBJECT_TYPE = f"{_DS_NS}Object"
_ORIGIN_RELATIONSHIP_TYPE = (
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin"
)
_SIGNATURE_RELATIONSHIP_TYPE = (
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature"
)
_RELATIONSHIPS_CONTENT_TYPE = "application/vnd.openxmlformats-package.relationships+xml"
_ORIGIN_CONTENT_TYPE = "application/vnd.openxmlformats-package.digital-signature-origin"
_SIGNATURE_CONTENT_TYPE = (
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"
)
_ORIGIN_PART = "_xmlsignatures/origin.sigs"
_ORIGIN_RELS_PART = "_xmlsignatures/_rels/origin.sigs.rels"
_SIGNATURE_PART = "_xmlsignatures/sig1.xml"


def write_signed_candidate(
    package_path: Path,
    candidate_path: Path,
    cert_pem: Path,
    key_pem: Path,
) -> CandidateArtifact:
    """Write one W3C XML-DSig-valid experimental OOXML candidate."""
    primitives = _signing_primitives()
    x509, hashes, serialization, padding, rsa, etree, invalid_signature = primitives

    package_path = Path(package_path)
    candidate = Path(candidate_path)
    if candidate.resolve() == package_path.resolve():
        raise InvalidDocumentError("signed candidate path must differ from its source path.")

    certificate, key = _load_signing_pair(
        cert_pem,
        key_pem,
        x509=x509,
        serialization=serialization,
    )
    _require_matching_rsa_keys(certificate, key, rsa=rsa, serialization=serialization)

    parts = _unsigned_package_parts(package_path)
    _add_signature_parts(
        parts,
        certificate,
        key,
        hashes=hashes,
        serialization=serialization,
        padding=padding,
        etree=etree,
    )
    _write_signed_package(candidate, parts)
    _verify_signed_package(
        candidate,
        x509=x509,
        hashes=hashes,
        padding=padding,
        rsa=rsa,
        etree=etree,
        invalid_signature=invalid_signature,
    )

    return CandidateArtifact(
        path=candidate,
        source_path=package_path,
        kind=ArtifactKind.OOXML,
        document_format=_format_from_part_names(parts),
        removed=RemovalCounts(),
    )


def _signing_primitives():
    """Import optional signing and C14N primitives with a product-level error."""
    try:
        import lxml.etree as etree
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:
        raise MissingDependencyError(
            "Signature re-sign requires the cryptography and lxml packages: "
            "pip install 'dietrich[sign]'."
        ) from exc
    return x509, hashes, serialization, padding, rsa, etree, InvalidSignature


def _load_signing_pair(cert_pem: Path, key_pem: Path, *, x509, serialization):
    """Load an unencrypted PEM certificate/private-key pair."""
    try:
        certificate = x509.load_pem_x509_certificate(Path(cert_pem).read_bytes())
        key = serialization.load_pem_private_key(Path(key_pem).read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise InvalidDocumentError("could not load the signing certificate/private key") from exc
    return certificate, key


def _require_matching_rsa_keys(certificate, key, *, rsa, serialization) -> None:
    """Reject non-RSA and mismatched certificate/private-key pairs."""
    certificate_key = certificate.public_key()
    if not isinstance(certificate_key, rsa.RSAPublicKey) or not isinstance(key, rsa.RSAPrivateKey):
        raise InvalidDocumentError("OOXML re-signing requires an RSA certificate and private key")
    try:
        certificate_bytes = certificate_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidDocumentError(
            "could not read the certificate/private-key public keys"
        ) from exc
    if not hmac.compare_digest(certificate_bytes, private_bytes):
        raise InvalidDocumentError("certificate and private key do not match")


def _unsigned_package_parts(package_path: Path) -> dict[str, bytes]:
    """Read every package part except a prior OOXML signature directory."""
    try:
        with zipfile.ZipFile(package_path) as archive:
            validate_archive_safety(archive, allow_signed=True)
            parts: dict[str, bytes] = {}
            for info in archive.infolist():
                checkpoint()
                name = info.filename.replace("\\", "/")
                if not name.lower().startswith("_xmlsignatures/"):
                    parts[name] = archive.read(info)
            return parts
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(f"cannot re-sign an invalid OOXML ZIP: {exc}") from exc


def _add_signature_parts(
    parts: dict[str, bytes],
    certificate,
    key,
    *,
    hashes,
    serialization,
    padding,
    etree,
) -> None:
    """Finalize discovery metadata, then add one enveloping XML signature."""
    parts["[Content_Types].xml"] = _signature_content_types(parts.get("[Content_Types].xml"), etree)
    parts["_rels/.rels"] = _root_relationships(parts.get("_rels/.rels"), etree)
    parts[_ORIGIN_PART] = b""
    parts[_ORIGIN_RELS_PART] = _origin_relationships(etree)

    references = _part_references(parts)
    parts[_SIGNATURE_PART] = _signature_xml(
        references,
        certificate,
        key,
        hashes=hashes,
        serialization=serialization,
        padding=padding,
        etree=etree,
    )


def _part_references(parts: dict[str, bytes]) -> list[tuple[str, str]]:
    """Hash finalized package bytes using unambiguous percent-encoded part URIs."""
    references: list[tuple[str, str]] = []
    for name in sorted(parts):
        checkpoint()
        uri = "/" + quote(name, safe="/")
        digest = base64.b64encode(hashlib.sha256(parts[name]).digest()).decode("ascii")
        references.append((uri, digest))
    return references


def _signature_xml(
    references: list[tuple[str, str]],
    certificate,
    key,
    *,
    hashes,
    serialization,
    padding,
    etree,
) -> bytes:
    """Build and sign the final Signature tree without later mutation."""
    ds = f"{{{_DS_NS}}}"
    signature = etree.Element(f"{ds}Signature", nsmap={None: _DS_NS})
    signature.set("Id", "idPackageSignature")

    signed_info = etree.SubElement(signature, f"{ds}SignedInfo")
    etree.SubElement(
        signed_info,
        f"{ds}CanonicalizationMethod",
        Algorithm=_C14N_ALGORITHM,
    )
    etree.SubElement(
        signed_info,
        f"{ds}SignatureMethod",
        Algorithm=_RSA_SHA256_ALGORITHM,
    )
    object_reference = etree.SubElement(
        signed_info,
        f"{ds}Reference",
        URI="#idPackageObject",
        Type=_OBJECT_TYPE,
    )
    transforms = etree.SubElement(object_reference, f"{ds}Transforms")
    etree.SubElement(transforms, f"{ds}Transform", Algorithm=_C14N_ALGORITHM)
    etree.SubElement(
        object_reference,
        f"{ds}DigestMethod",
        Algorithm=_SHA256_ALGORITHM,
    )
    object_digest = etree.SubElement(object_reference, f"{ds}DigestValue")

    signature_value = etree.SubElement(signature, f"{ds}SignatureValue")
    key_info = etree.SubElement(signature, f"{ds}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{ds}X509Data")
    certificate_node = etree.SubElement(x509_data, f"{ds}X509Certificate")
    certificate_node.text = base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)
    ).decode("ascii")

    package_object = etree.SubElement(signature, f"{ds}Object", Id="idPackageObject")
    manifest = etree.SubElement(package_object, f"{ds}Manifest")
    for uri, digest in references:
        reference = etree.SubElement(manifest, f"{ds}Reference", URI=uri)
        etree.SubElement(reference, f"{ds}DigestMethod", Algorithm=_SHA256_ALGORITHM)
        etree.SubElement(reference, f"{ds}DigestValue").text = digest

    object_digest.text = _sha256_b64(_canonical_bytes(package_object, etree))
    signature_value.text = base64.b64encode(
        key.sign(
            _canonical_bytes(signed_info, etree),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    return etree.tostring(
        signature,
        encoding="UTF-8",
        xml_declaration=True,
        pretty_print=False,
    )


def _canonical_bytes(element, etree) -> bytes:
    return etree.tostring(
        element,
        method="c14n",
        exclusive=False,
        with_comments=False,
    )


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _signature_content_types(raw: bytes | None, etree) -> bytes:
    """Preserve package mappings while replacing signature content declarations."""
    qname = f"{{{_CONTENT_TYPES_NS}}}"
    if raw is None:
        root = etree.Element(f"{qname}Types", nsmap={None: _CONTENT_TYPES_NS})
    else:
        root = _parse_xml(raw, etree, "[Content_Types].xml")
        if root.tag != f"{qname}Types":
            raise InvalidDocumentError("[Content_Types].xml has an unexpected root element")

    for child in list(root):
        if child.tag != f"{qname}Override":
            continue
        part_name = child.get("PartName", "")
        if part_name.casefold().startswith("/_xmlsignatures/"):
            root.remove(child)

    defaults = {
        child.get("Extension", "").casefold() for child in root if child.tag == f"{qname}Default"
    }
    if "rels" not in defaults:
        etree.SubElement(
            root,
            f"{qname}Default",
            Extension="rels",
            ContentType=_RELATIONSHIPS_CONTENT_TYPE,
        )
    etree.SubElement(
        root,
        f"{qname}Override",
        PartName=f"/{_ORIGIN_PART}",
        ContentType=_ORIGIN_CONTENT_TYPE,
    )
    etree.SubElement(
        root,
        f"{qname}Override",
        PartName=f"/{_SIGNATURE_PART}",
        ContentType=_SIGNATURE_CONTENT_TYPE,
    )
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=False)


def _root_relationships(raw: bytes | None, etree) -> bytes:
    """Preserve root relationships and add one origin relationship with a free ID."""
    qname = f"{{{_RELATIONSHIPS_NS}}}"
    if raw is None:
        root = etree.Element(
            f"{qname}Relationships",
            nsmap={None: _RELATIONSHIPS_NS},
        )
    else:
        root = _parse_xml(raw, etree, "_rels/.rels")
        if root.tag != f"{qname}Relationships":
            raise InvalidDocumentError("_rels/.rels has an unexpected root element")

    for child in list(root):
        if child.tag == f"{qname}Relationship" and child.get("Type") == _ORIGIN_RELATIONSHIP_TYPE:
            root.remove(child)
    used_ids = {
        child.get("Id") for child in root if child.tag == f"{qname}Relationship" and child.get("Id")
    }
    identifier = "rIdSig"
    suffix = 1
    while identifier in used_ids:
        identifier = f"rIdSig{suffix}"
        suffix += 1
    etree.SubElement(
        root,
        f"{qname}Relationship",
        Id=identifier,
        Type=_ORIGIN_RELATIONSHIP_TYPE,
        Target=_ORIGIN_PART,
    )
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=False)


def _origin_relationships(etree) -> bytes:
    """Point the signature origin at the signature XML part."""
    qname = f"{{{_RELATIONSHIPS_NS}}}"
    root = etree.Element(
        f"{qname}Relationships",
        nsmap={None: _RELATIONSHIPS_NS},
    )
    etree.SubElement(
        root,
        f"{qname}Relationship",
        Id="rId1",
        Type=_SIGNATURE_RELATIONSHIP_TYPE,
        Target="sig1.xml",
    )
    return etree.tostring(root, encoding="UTF-8", xml_declaration=True, pretty_print=False)


def _parse_xml(data: bytes, etree, label: str):
    """Parse package metadata without DTDs, entities, network access, or recovery."""
    if b"<!DOCTYPE" in data.upper():
        raise InvalidDocumentError(f"{label} must not contain a document type declaration")
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        recover=False,
        huge_tree=False,
        remove_comments=False,
    )
    try:
        root = etree.fromstring(data, parser=parser)
    except (ValueError, etree.XMLSyntaxError) as exc:
        raise InvalidDocumentError(f"{label} is malformed XML") from exc
    if root.getroottree().docinfo.doctype:
        raise InvalidDocumentError(f"{label} must not contain a document type declaration")
    return root


def _write_signed_package(output_path: Path, parts: dict[str, bytes]) -> None:
    """Write a fully assembled signed package to an unpublished path."""
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            checkpoint()
            archive.writestr(name, data)


def _verify_signed_package(
    path: Path,
    *,
    x509,
    hashes,
    padding,
    rsa,
    etree,
    invalid_signature,
) -> None:
    """Reopen and cryptographically validate the exact bytes to be published."""
    try:
        with zipfile.ZipFile(path) as archive:
            validate_archive_safety(archive, allow_signed=True)
            failed_member = verify_archive_crc(archive)
            if failed_member is not None:
                raise InvalidDocumentError(
                    f"written signed package failed ZIP verification at {failed_member}"
                )
            parts = {
                info.filename.replace("\\", "/"): archive.read(info) for info in archive.infolist()
            }
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(f"written signed package is not a valid ZIP: {exc}") from exc

    try:
        _verify_signature_parts(
            parts,
            x509=x509,
            hashes=hashes,
            padding=padding,
            rsa=rsa,
            etree=etree,
            invalid_signature=invalid_signature,
        )
    except InvalidDocumentError:
        raise
    except (KeyError, TypeError, ValueError, etree.XMLSyntaxError) as exc:
        raise InvalidDocumentError(
            "written signed package failed XML signature verification"
        ) from exc


def _verify_signature_parts(
    parts: dict[str, bytes],
    *,
    x509,
    hashes,
    padding,
    rsa,
    etree,
    invalid_signature,
) -> None:
    """Validate SignatureValue, Object digest, and every referenced ZIP part."""
    if parts.get(_ORIGIN_PART) != b"" or _ORIGIN_RELS_PART not in parts:
        raise InvalidDocumentError("written signed package has an invalid signature origin")
    raw_signature = parts.get(_SIGNATURE_PART)
    if raw_signature is None:
        raise InvalidDocumentError("written signed package is missing its signature XML")

    signature = _parse_xml(raw_signature, etree, _SIGNATURE_PART)
    ds = f"{{{_DS_NS}}}"
    if signature.tag != f"{ds}Signature":
        raise InvalidDocumentError("written signature has an unexpected root element")
    signed_info = _one(signature.findall(f"{ds}SignedInfo"), "SignedInfo")
    signature_value = _one(signature.findall(f"{ds}SignatureValue"), "SignatureValue")
    package_object = _one(
        signature.xpath("./ds:Object[@Id='idPackageObject']", namespaces={"ds": _DS_NS}),
        "package Object",
    )
    certificate_node = _one(
        signature.xpath(
            "./ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            namespaces={"ds": _DS_NS},
        ),
        "X509Certificate",
    )

    canonicalization = _one(
        signed_info.findall(f"{ds}CanonicalizationMethod"),
        "CanonicalizationMethod",
    )
    signature_method = _one(
        signed_info.findall(f"{ds}SignatureMethod"),
        "SignatureMethod",
    )
    if canonicalization.get("Algorithm") != _C14N_ALGORITHM:
        raise InvalidDocumentError("written signature uses an unsupported canonicalization")
    if signature_method.get("Algorithm") != _RSA_SHA256_ALGORITHM:
        raise InvalidDocumentError("written signature uses an unsupported signature algorithm")

    reference = _one(signed_info.findall(f"{ds}Reference"), "SignedInfo Reference")
    if reference.get("URI") != "#idPackageObject" or reference.get("Type") != _OBJECT_TYPE:
        raise InvalidDocumentError("written signature does not reference its package Object")
    transform = _one(
        reference.findall(f"{ds}Transforms/{ds}Transform"),
        "Object canonicalization transform",
    )
    if transform.get("Algorithm") != _C14N_ALGORITHM:
        raise InvalidDocumentError("written Object reference uses an unsupported transform")
    _require_sha256(reference, ds)
    expected_object_digest = _text(_one(reference.findall(f"{ds}DigestValue"), "DigestValue"))
    if not hmac.compare_digest(
        expected_object_digest,
        _sha256_b64(_canonical_bytes(package_object, etree)),
    ):
        raise InvalidDocumentError("written signature Object digest does not match")

    try:
        certificate = x509.load_der_x509_certificate(
            base64.b64decode(_text(certificate_node), validate=True)
        )
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise InvalidDocumentError("written signature certificate is not RSA")
        public_key.verify(
            base64.b64decode(_text(signature_value), validate=True),
            _canonical_bytes(signed_info, etree),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except invalid_signature as exc:
        raise InvalidDocumentError("written SignatureValue does not verify") from exc
    except (TypeError, ValueError) as exc:
        raise InvalidDocumentError("written signature contains invalid certificate data") from exc

    manifest = _one(package_object.findall(f"{ds}Manifest"), "Manifest")
    referenced: set[str] = set()
    for part_reference in manifest.findall(f"{ds}Reference"):
        checkpoint()
        _require_sha256(part_reference, ds)
        uri = part_reference.get("URI")
        if not uri or not uri.startswith("/") or uri.startswith("//"):
            raise InvalidDocumentError("written Manifest contains an invalid package URI")
        encoded_name = uri[1:]
        name = unquote(encoded_name)
        if not name or quote(name, safe="/") != encoded_name or name in referenced:
            raise InvalidDocumentError("written Manifest contains an ambiguous package URI")
        data = parts.get(name)
        if data is None:
            raise InvalidDocumentError(f"written Manifest references a missing part: {name}")
        expected = _text(_one(part_reference.findall(f"{ds}DigestValue"), "Manifest DigestValue"))
        if not hmac.compare_digest(expected, _sha256_b64(data)):
            raise InvalidDocumentError(f"written Manifest digest does not match: {name}")
        referenced.add(name)

    expected_parts = set(parts) - {_SIGNATURE_PART}
    if referenced != expected_parts:
        raise InvalidDocumentError("written Manifest does not cover every finalized package part")


def _require_sha256(reference, ds: str) -> None:
    digest_method = _one(reference.findall(f"{ds}DigestMethod"), "DigestMethod")
    if digest_method.get("Algorithm") != _SHA256_ALGORITHM:
        raise InvalidDocumentError("written signature uses an unsupported digest algorithm")


def _one(values: list, label: str):
    if len(values) != 1:
        raise InvalidDocumentError(f"written signature must contain exactly one {label}")
    return values[0]


def _text(element) -> str:
    value = element.text
    if not isinstance(value, str) or not value.strip():
        raise InvalidDocumentError("written signature contains an empty required value")
    return value.strip()


def _format_from_part_names(parts: dict[str, bytes]) -> DocumentFormat:
    """Identify the OOXML family from retained package part names."""
    from dietrich.ooxml.package import identify_ooxml_format

    return identify_ooxml_format(list(parts))
