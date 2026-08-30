"""OOXML-owned digital-signature transformations."""

from dietrich.ooxml.signatures.resign import write_signed_candidate
from dietrich.ooxml.signatures.strip import strip_signature_members

__all__ = ["strip_signature_members", "write_signed_candidate"]
