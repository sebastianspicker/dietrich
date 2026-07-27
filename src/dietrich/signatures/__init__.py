"""OOXML digital signature strip / honest re-sign helpers."""

from dietrich.signatures.resign import resign_ooxml_package
from dietrich.signatures.strip import strip_signature_members

__all__ = ["resign_ooxml_package", "strip_signature_members"]
