"""Deterministic parsing and validation contracts for native PDF hashes."""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from dietrich.crypto import pdf_hash
from dietrich.errors import EncryptedDocumentError


def test_extract_balanced_encrypt_dictionary_preserves_nested_crypt_filter() -> None:
    raw = (
        b"prefix << /Filter /Standard /CF << /StdCF << /CFM /AESV2 >> >> "
        b"/O <aabb> /U <ccdd> >> suffix"
    )

    body = pdf_hash._extract_balanced_dict(raw, 0)

    assert body is not None
    parsed = pdf_hash._parse_dict_body(body)
    assert parsed["Filter"] == "/Standard"
    assert parsed["CFM"] == "/AESV2"
    assert parsed["O"] == "<aabb>"
    assert parsed["U"] == "<ccdd>"


def test_trailer_parses_inline_encrypt_dictionary() -> None:
    raw = (
        b"%PDF-1.7\ntrailer << /Size 2 /Encrypt << /Filter /Standard /R 4 "
        b"/O <aabb> /U <ccdd> /CF << /StdCF << /CFM /AESV2 >> >> >> >>"
    )

    parsed = pdf_hash._trailer_encrypt_dict(raw)

    assert parsed is not None
    assert parsed["Filter"] == "/Standard"
    assert parsed["R"] == "4"
    assert parsed["O"] == "<aabb>"
    assert parsed["U"] == "<ccdd>"


def test_trailer_resolves_indirect_encrypt_dictionary() -> None:
    raw = (
        b"%PDF-1.7\n17 0 obj\n<< /Filter /Standard /R 4 /O <aabb> /U <ccdd> >>\n"
        b"endobj\ntrailer << /Size 18 /Encrypt 17 0 R >>"
    )

    assert pdf_hash._trailer_encrypt_dict(raw) == {
        "Filter": "/Standard",
        "R": "4",
        "O": "<aabb>",
        "U": "<ccdd>",
    }


def test_trailer_search_uses_bounded_auxiliary_memory() -> None:
    raw = (b"trailer not-a-dictionary\n" * 100_000) + (
        b"trailer << /Encrypt << /Filter /Standard /R 4 /O <aa> /U <bb> >> >>"
    )
    tracemalloc.start()
    try:
        parsed = pdf_hash._trailer_encrypt_dict(raw)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert parsed is not None
    assert parsed["O"] == "<aa>"
    assert peak < 500_000


def test_unterminated_encrypt_dictionary_is_rejected() -> None:
    assert pdf_hash._extract_balanced_dict(b"<< /Filter /Standard /O <aa>", 0) is None
    assert pdf_hash._referenced_encrypt_dict(b"3 0 obj << /O <aa>", 3, 0) is None


def test_literal_strings_decode_named_octal_and_delimiter_escapes() -> None:
    value = r"(A\nB\053\(\)\\)"

    assert pdf_hash._literal_string_hex(value) == b"A\nB+()\\".hex()


@pytest.mark.parametrize(
    ("length", "revision", "cfm", "expected"),
    [
        (None, 2, "", 40),
        (None, 3, "", 128),
        (5, 4, "", 40),
        (16, 4, "/AESV2", 128),
        (128, 4, "/AESV2", 128),
        (None, 5, "", 256),
        (128, 3, "/AESV3", 256),
    ],
)
def test_pdf_key_bits_normalizes_rc4_and_aes_lengths(
    length: int | None, revision: int, cfm: str, expected: int
) -> None:
    assert pdf_hash._pdf_key_bits(length=length, r=revision, cfm=cfm) == expected


def test_pdf_hash_fields_normalize_literal_fields_and_default_file_id() -> None:
    revision, fields = pdf_hash._pdf_hash_fields(
        Path("locked.pdf"),
        b"%PDF-1.7",
        {
            "R": "4",
            "V": "4",
            "P": "-4",
            "Length": "16",
            "Filter": "/Standard",
            "CFM": "/AESV2",
            "O": r"(A\053)",
            "U": "<CCDD>",
        },
    )

    assert revision == 4
    assert fields.version == 4
    assert fields.permissions == -4
    assert fields.key_bits == 128
    assert fields.owner_hex == "412b"
    assert fields.user_hex == "ccdd"
    assert fields.file_id_hex == "00" * 16


@pytest.mark.parametrize(
    ("encrypt", "message"),
    [
        ({"R": "4", "U": "<ccdd>"}, "missing /O or /U"),
        (
            {"R": "4", "O": "<aabb>", "U": "<ccdd>", "Filter": "/Adobe.PubSec"},
            "unsupported security handler",
        ),
    ],
)
def test_pdf_hash_fields_reject_missing_or_unsupported_handler_values(
    encrypt: dict[str, str], message: str
) -> None:
    with pytest.raises(EncryptedDocumentError, match=message):
        pdf_hash._pdf_hash_fields(Path("locked.pdf"), b"%PDF-1.7", encrypt)


def test_aes256_hash_requires_all_modern_binary_fields() -> None:
    fields = pdf_hash._PdfHashFields(5, -4, 256, "aa", "bb", "00" * 16)

    with pytest.raises(EncryptedDocumentError, match=r"requires /OE /UE /Perms"):
        pdf_hash._aes256_pdf_hash(Path("locked.pdf"), {"OE": "<00>", "UE": "<11>"}, 5, fields)


def test_export_pdf_hash_rejects_unsupported_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "locked.pdf"
    path.write_bytes(b"%PDF-1.7")
    monkeypatch.setattr(
        pdf_hash,
        "_encrypt_dict_via_pikepdf",
        lambda _path: {"R": "7", "O": "<aabb>", "U": "<ccdd>"},
    )

    with pytest.raises(EncryptedDocumentError, match=r"unsupported PDF revision R=7"):
        pdf_hash.export_pdf_hash(path)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"%PDF\ntrailer << /ID [<aabbccdd> <0011>] >>", "aabbccdd"),
        (b"%PDF\ntrailer << /ID [<aa bb\ncc> <0011>] >>", "aabbcc"),
        (rb"%PDF\ntrailer << /ID [(doc\053id) (unused)] >>", b"doc+id".hex()),
        (
            b"%PDF\ntrailer << /ID [(doc\\\r\ncontinued) (unused)] >>",
            b"doccontinued".hex(),
        ),
    ],
)
def test_file_id_parses_complete_hex_and_literal_values(raw: bytes, expected: str) -> None:
    assert pdf_hash._file_id_hex(raw) == expected
