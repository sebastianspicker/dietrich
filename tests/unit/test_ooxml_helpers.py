"""Direct contract coverage for OOXML VBA, property, and signature helpers."""

from __future__ import annotations

import io
import zipfile

from defusedxml import ElementTree

from dietrich.ooxml.props import (
    APP_PROPS,
    CUSTOM_PROPS,
    inspect_props_parts,
    transform_props_part,
)
from dietrich.ooxml.vba import (
    _apply_ole_patches,
    _ole_vba_patches,
    _unlock_ole_vba,
    unlock_vba_project,
)
from dietrich.signatures.strip import CONTENT_TYPES, strip_signature_members
from dietrich.types import PartStats, UnlockOptions


def test_unlock_vba_project_clears_keys_without_changing_record_length() -> None:
    source = b"CMG=alpha\r\nDPB = beta\nGc=gamma\r\nOther=keep"

    unlocked, touched = unlock_vba_project(source)

    assert touched == 3
    assert len(unlocked) == len(source)
    assert unlocked == b'CMG=""   \r\nDPB=""    \nGc=""   \r\nOther=keep'


def test_unlock_vba_project_falls_back_from_malformed_ole_and_keeps_blank_values() -> None:
    malformed_ole = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1CMG=secret\nDPB=""\n'

    unlocked, touched = unlock_vba_project(malformed_ole)

    assert touched == 1
    assert unlocked.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1CMG=""')
    assert b'DPB=""' in unlocked


def test_ole_vba_patch_selection_prefers_project_streams_and_rewrites_once() -> None:
    project = b"CMG=secret\r\nDPB=locked"

    class FakeOle:
        streams = {
            "VBA/PROJECT": project,
            "VBA/Module1": b"CMG=module-marker",
        }

        def listdir(self, *, streams: bool, storages: bool) -> list[list[str]]:
            assert streams is True and storages is False
            return [name.split("/") for name in self.streams]

        def openstream(self, parts: list[str]) -> io.BytesIO:
            return io.BytesIO(self.streams["/".join(parts)])

    patches, touched = _ole_vba_patches(FakeOle())
    rewritten = _apply_ole_patches(b"prefix" + project + project, patches)

    assert touched == 2
    assert len(patches) == 1
    assert b'CMG=""' in rewritten
    assert rewritten.count(project) == 1


def test_unlock_ole_vba_falls_back_for_non_ole_payload() -> None:
    class NotOleApi:
        @staticmethod
        def isOleFile(_stream: io.BytesIO) -> bool:
            return False

    unlocked, touched = _unlock_ole_vba(b"GC=locked", NotOleApi)

    assert unlocked == b'GC=""    '
    assert touched == 1


def test_inspect_props_parts_reports_active_docsecurity_and_custom_flags() -> None:
    parts = {
        APP_PROPS: b"<Properties><DocSecurity>4</DocSecurity></Properties>",
        CUSTOM_PROPS: b'<Properties><property name="_MarkAsFinal"/></Properties>',
    }

    protections = inspect_props_parts(list(parts), parts.__getitem__)

    assert [(part.path, part.kind, part.count) for part in protections] == [
        (APP_PROPS, "DocSecurity", 1),
        (CUSTOM_PROPS, "MarkAsFinal", 1),
    ]


def test_transform_props_part_clears_docsecurity_only_when_enabled() -> None:
    source = b"<Properties><DocSecurity>8</DocSecurity><Company>Keep</Company></Properties>"
    stats = PartStats()

    disabled = transform_props_part(
        APP_PROPS,
        source,
        UnlockOptions(remove_mark_as_final=False),
        stats,
    )
    cleared = transform_props_part(APP_PROPS, source, UnlockOptions(), stats)

    assert disabled == source
    assert cleared == (
        b"<Properties><DocSecurity>0</DocSecurity><Company>Keep</Company></Properties>"
    )
    assert stats.counts == {"markAsFinal": 1}


def test_transform_props_part_removes_only_mark_as_final_custom_properties() -> None:
    source = (
        b'<?xml version="1.0"?><Properties>'
        b'<property name="_MarkAsFinal"><value>true</value></property>'
        b'<property name="Keep"><value>present</value></property>'
        b'<property name="MarkAsFinalStatus"><value>true</value></property>'
        b"</Properties>"
    )
    stats = PartStats()

    transformed = transform_props_part(CUSTOM_PROPS, source, UnlockOptions(), stats)
    root = ElementTree.fromstring(transformed)
    property_names = [element.attrib["name"] for element in root]

    assert property_names == ["Keep"]
    assert stats.counts == {"markAsFinal": 2}
    assert transformed.startswith(b'<?xml version="1.0"?>\n')


def test_transform_props_part_uses_pattern_fallback_for_malformed_custom_xml() -> None:
    source = b'<Properties><property name="MarkAsFinal">remove</property><broken>'
    stats = PartStats()

    transformed = transform_props_part(CUSTOM_PROPS, source, UnlockOptions(), stats)

    assert transformed == b"<Properties><broken>"
    assert stats.counts == {"markAsFinal": 1}


def test_strip_signature_members_rewrites_synthetic_signed_zip_metadata() -> None:
    content_types = (
        b'<?xml version="1.0"?><Types>'
        b'<Override PartName="/word/document.xml" ContentType="application/xml"/>'
        b'<Override PartName="/_xmlsignatures/sig1.xml" ContentType="application/xml"/>'
        b'<Default Extension="sigs" '
        b'ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/>'
        b"</Types>"
    )
    root_rels = (
        b'<Relationships><Relationship Id="keep" Type="urn:keep" Target="word/document.xml"/>'
        b'<Relationship Id="sig" Type="urn:digital-signature/origin" '
        b'Target="_xmlsignatures/origin.sigs"/>'
        b"</Relationships>"
    )
    discovered_rels = (
        b'<Relationships><Relationship Id="keep" Type="urn:keep" Target="metadata.xml"/>'
        b'<Relationship Id="sig" Type="urn:keep" Target="../_xmlsignatures/sig1.xml"/>'
        b"</Relationships>"
    )
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr(CONTENT_TYPES, content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("custom/_rels/metadata.rels", discovered_rels)
        archive.writestr("word/document.xml", b"<document/>")
        archive.writestr("_xmlsignatures/sig1.xml", b"<signature/>")

    with zipfile.ZipFile(archive_bytes) as archive:
        skip, rewritten = strip_signature_members(archive.namelist(), archive.read)

    assert skip == {"_xmlsignatures/sig1.xml"}
    assert set(rewritten) == {CONTENT_TYPES, "_rels/.rels", "custom/_rels/metadata.rels"}
    assert b"xmlsignatures" not in rewritten[CONTENT_TYPES].lower()
    assert b"digital-signature" not in rewritten[CONTENT_TYPES].lower()
    assert b'PartName="/word/document.xml"' in rewritten[CONTENT_TYPES]
    assert b'Target="word/document.xml"' in rewritten["_rels/.rels"]
    assert b"_xmlsignatures" not in rewritten["_rels/.rels"].lower()
    assert b'Target="metadata.xml"' in rewritten["custom/_rels/metadata.rels"]
    assert b"_xmlsignatures" not in rewritten["custom/_rels/metadata.rels"].lower()


def test_strip_signature_members_is_a_noop_without_signature_parts() -> None:
    def fail_if_read(_name: str) -> bytes:
        raise AssertionError("an unsigned package must not read metadata")

    skip, rewritten = strip_signature_members(
        [CONTENT_TYPES, "_rels/.rels", "word/document.xml"],
        fail_if_read,
    )

    assert skip == set()
    assert rewritten == {}


def test_strip_signature_members_preserves_malformed_metadata_bytes() -> None:
    malformed_parts = {
        CONTENT_TYPES: b"<Types><broken>",
        "_rels/.rels": b"<Relationships><broken>",
    }
    names = [*malformed_parts, "_xmlsignatures/sig1.xml"]

    skip, rewritten = strip_signature_members(names, malformed_parts.__getitem__)

    assert skip == {"_xmlsignatures/sig1.xml"}
    assert rewritten == malformed_parts
