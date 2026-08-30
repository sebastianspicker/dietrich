"""Unpublished artifact records returned by document-format writers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from dietrich.domain.models import DocumentFormat, RemovalCounts


class ArtifactKind(StrEnum):
    """Validation strategy for an unpublished candidate file."""

    OOXML = "ooxml"
    PDF = "pdf"
    LEGACY_OFFICE = "legacy_office"


@dataclass(frozen=True)
class CandidateArtifact:
    """A transformed and still-unpublished document candidate."""

    path: Path
    source_path: Path
    kind: ArtifactKind
    document_format: DocumentFormat
    removed: RemovalCounts
    vba_project_present: bool = False
    password_used: str | None = None
    warnings: tuple[str, ...] = ()


__all__ = ["ArtifactKind", "CandidateArtifact"]
