"""Regression tests for memory-bounded prefix probes."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from dietrich.safety.bounded_io import (
    read_file_limited,
    read_file_prefix,
    read_zip_member_prefix,
)


@pytest.mark.parametrize("limit", [2, 8, 4_000, 65_536, 200_000])
def test_read_file_prefix_respects_exact_limit(tmp_path: Path, limit: int) -> None:
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"A" * (limit + 17))

    assert read_file_prefix(path, limit) == b"A" * limit


def test_read_file_prefix_rejects_negative_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        read_file_prefix(tmp_path / "unused.bin", -1)


class _RecordingMember(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_sizes: list[int] = []

    def read(self, size: int | None = -1) -> bytes:
        size = -1 if size is None else size
        self.read_sizes.append(size)
        if size < 0:
            raise AssertionError("unbounded ZIP member read")
        return super().read(size)


class _RecordingArchive:
    def __init__(self, member: _RecordingMember) -> None:
        self.member = member

    def open(self, name: str) -> _RecordingMember:
        assert name == "customXml/item.xml"
        return self.member


def test_file_prefix_uses_one_bounded_read(monkeypatch: pytest.MonkeyPatch) -> None:
    member = _RecordingMember(b"A" * 1_000_000)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: member)

    assert read_file_prefix(Path("oversized.bin"), 8) == b"A" * 8
    assert member.read_sizes == [8]
    assert member.closed


def test_file_limited_rejects_input_beyond_cap(tmp_path: Path) -> None:
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"A" * 9)

    with pytest.raises(ValueError, match="8-byte processing limit"):
        read_file_limited(path, 8)


def test_file_limited_accepts_exact_cap(tmp_path: Path) -> None:
    path = tmp_path / "bounded.bin"
    path.write_bytes(b"A" * 8)

    assert read_file_limited(path, 8) == b"A" * 8


def test_zip_member_prefix_stops_after_bounded_read() -> None:
    member = _RecordingMember(b"rightsmanagement" + b"A" * 200_000)
    archive = _RecordingArchive(member)

    prefix = read_zip_member_prefix(archive, "customXml/item.xml", 4_000)  # type: ignore[arg-type]

    assert prefix.startswith(b"rightsmanagement")
    assert member.read_sizes == [4_000]
    assert member.closed


def test_zip_member_prefix_does_not_process_corrupt_tail(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.zip"
    payload = b"A" * 8_192
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("customXml/item.xml", payload)
    raw = bytearray(path.read_bytes())
    offset = raw.find(payload)
    assert offset >= 0
    raw[offset + 6_000] ^= 0xFF
    path.write_bytes(raw)

    with zipfile.ZipFile(path) as archive:
        assert read_zip_member_prefix(archive, "customXml/item.xml", 4_000) == payload[:4_000]


def test_detect_consumers_request_only_their_documented_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dietrich.crypto import detect
    from dietrich.types import DocumentFormat, DocumentInspection

    path = tmp_path / "input.bin"
    path.write_bytes(b"input")
    calls: list[int] = []

    def read_prefix(_path: Path, limit: int) -> bytes:
        calls.append(limit)
        if limit == 65_536:
            return b"EncryptionInfo"
        return detect.CFBF_MAGIC if len(calls) == 3 else b"unknown!"

    monkeypatch.setattr(detect, "read_file_prefix", read_prefix)
    assert detect.classify_path(path).document_format == DocumentFormat.UNKNOWN
    assert detect._cfbf_heuristic_summary(path, [], [])[0] == DocumentFormat.ENCRYPTED_OOXML
    monkeypatch.setattr(
        detect,
        "_classify_cfbf",
        lambda candidate: DocumentInspection(
            input_path=candidate,
            document_format=DocumentFormat.ENCRYPTED_OOXML,
            strategies=(),
        ),
    )
    assert detect.detect_encrypted_ooxml(path) is True
    assert calls == [8, 65_536, 8]


def test_irm_consumers_bound_file_and_zip_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dietrich.crypto import irm

    path = tmp_path / "input.bin"
    path.write_bytes(b"input")
    file_limits: list[int] = []
    zip_limits: list[int] = []

    monkeypatch.setattr(
        irm,
        "read_file_prefix",
        lambda _path, limit: file_limits.append(limit) or b"unknown!",
    )
    assert irm.detect_irm(path).is_irm is False

    class Archive:
        def namelist(self) -> list[str]:
            return ["customXml/item.xml"]

    monkeypatch.setattr(
        irm,
        "read_zip_member_prefix",
        lambda _archive, _name, limit: zip_limits.append(limit) or b"rightsmanagement",
    )
    assert irm._custom_xml_rights_part(Archive(), Archive().namelist()) == "customXml/item.xml"
    assert file_limits == [8]
    assert zip_limits == [4_000]


def test_pdf_fallback_requests_only_inspection_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from dietrich.pdf import inspect as pdf_inspect

    path = tmp_path / "input.pdf"
    path.write_bytes(b"%PDF-input")
    limits: list[int] = []
    monkeypatch.setitem(sys.modules, "pikepdf", None)
    monkeypatch.setattr(
        pdf_inspect,
        "read_file_prefix",
        lambda _path, limit: limits.append(limit) or b"%PDF- /Encrypt",
    )

    inspection = pdf_inspect.inspect_pdf(path)
    assert inspection.encrypted is True
    assert limits == [200_000]


def test_resign_probe_requests_only_magic_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dietrich import dispatch
    from dietrich.errors import UnsupportedFormatError
    from dietrich.types import DocumentFormat, RemovalCounts, UnlockOptions, UnlockResult

    output = tmp_path / "output.bin"
    output.write_bytes(b"not a ZIP")
    limits: list[int] = []
    monkeypatch.setattr(
        dispatch,
        "read_file_prefix",
        lambda _path, limit: limits.append(limit) or b"NO",
    )
    result = UnlockResult(output, output, RemovalCounts(), DocumentFormat.LEGACY_CFBF)
    options = UnlockOptions(resign_cert=tmp_path / "cert.pem", resign_key=tmp_path / "key.pem")

    with pytest.raises(UnsupportedFormatError, match="cannot --resign"):
        dispatch._maybe_resign(result, options)
    assert limits == [2]


def test_decrypted_zip_is_safety_checked_before_integrity_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dietrich import dispatch
    from dietrich.safety import zip_archive

    path = tmp_path / "decrypted.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", b"<document/>")

    calls: list[str] = []
    monkeypatch.setattr(
        zip_archive,
        "validate_archive_safety",
        lambda _archive, *, allow_signed: calls.append(f"validate:{allow_signed}"),
    )
    monkeypatch.setattr(
        zipfile.ZipFile,
        "testzip",
        lambda _archive: calls.append("testzip") or None,
    )

    dispatch._verify_decrypted_output(path)

    assert calls == ["validate:True", "testzip"]


def test_irm_custom_xml_runtime_failure_is_best_effort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dietrich.crypto import irm

    class Archive:
        pass

    monkeypatch.setattr(
        irm,
        "read_zip_member_prefix",
        lambda *_args: (_ for _ in ()).throw(
            RuntimeError("encrypted ZIP member requires a password")
        ),
    )

    assert irm._custom_xml_rights_part(Archive(), ["customXml/item.xml"]) is None


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"<rightsmanagement/>" + b"A" * 8_000, True),
        (b"A" * 4_000 + b"<rightsmanagement/>", False),
    ],
)
def test_irm_detection_preserves_documented_prefix_boundary(
    tmp_path: Path, payload: bytes, expected: bool
) -> None:
    from dietrich.crypto.irm import detect_irm

    path = tmp_path / "input.xlsx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("customXml/item.xml", payload)

    assert detect_irm(path).is_irm is expected


def test_irm_zip_safety_failure_becomes_limited_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dietrich.crypto import irm
    from dietrich.errors import UnsafeArchiveError

    path = tmp_path / "input.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("customXml/item.xml", b"rightsmanagement")
    monkeypatch.setattr(
        irm,
        "validate_archive_safety",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(UnsafeArchiveError("oversized")),
    )

    details: list[str] = []
    assert irm._probe_zip_irm(path, details) is None
    assert details == ["ZIP IRM probe limited: oversized"]


def test_irm_corrupt_zip_becomes_limited_diagnostic(tmp_path: Path) -> None:
    from dietrich.crypto.irm import detect_irm

    path = tmp_path / "corrupt.xlsx"
    path.write_bytes(b"PK\x03\x04not-a-valid-archive")

    info = detect_irm(path)
    assert info.is_irm is False
    assert any("ZIP IRM probe limited" in detail for detail in info.details)
