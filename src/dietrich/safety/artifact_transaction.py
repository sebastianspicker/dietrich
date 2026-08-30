"""Private staging and single-point publication for transformed documents."""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from dietrich.domain.artifacts import ArtifactKind, CandidateArtifact
from dietrich.errors import InvalidDocumentError, OutputExistsError
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.safety.zip_archive import validate_archive_safety


class ArtifactTransaction:
    """Own private candidates and publish exactly one validated final artifact."""

    def __init__(self, target: Path, *, overwrite: bool, mode: int = 0o600) -> None:
        self.target = Path(target)
        self.overwrite = overwrite
        self.mode = mode
        self._workspace: tempfile.TemporaryDirectory[str] | None = None
        self._counter = 0

    def __enter__(self) -> ArtifactTransaction:
        if self.target.exists() and not self.overwrite:
            raise OutputExistsError(f"{self.target} already exists.")
        self._workspace = tempfile.TemporaryDirectory(
            prefix=f".{self.target.name}.work.", dir=self.target.parent
        )
        os.chmod(self._workspace.name, 0o700)
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._workspace is not None:
            self._workspace.cleanup()

    def candidate_path(self, suffix: str = ".bin") -> Path:
        """Allocate a unique path inside the private transaction workspace."""
        if self._workspace is None:
            raise RuntimeError("artifact transaction is not active")
        self._counter += 1
        return Path(self._workspace.name) / f"candidate-{self._counter}{suffix}"

    def snapshot_source(self, source: Path) -> Path:
        """Copy one input into the private workspace for stable repeated parsing."""
        snapshot = self.candidate_path(Path(source).suffix or ".bin")
        shutil.copyfile(source, snapshot)
        os.chmod(snapshot, self.mode)
        return snapshot

    def commit(
        self,
        artifact: CandidateArtifact,
        *,
        validate_semantics: Callable[[CandidateArtifact], None],
    ) -> None:
        """Validate, make private, and atomically publish one candidate."""
        validate_semantics(artifact)
        validate_candidate(artifact)
        with temporary_output_path(self.target) as adjacent:
            shutil.copyfile(artifact.path, adjacent)
            os.chmod(adjacent, self.mode)
            with adjacent.open("rb") as stream:
                os.fsync(stream.fileno())
            publish_output(adjacent, self.target, overwrite=self.overwrite)
        _fsync_directory(self.target.parent)


def validate_candidate(artifact: CandidateArtifact) -> None:
    """Validate a candidate according to its concrete artifact kind."""
    if artifact.kind == ArtifactKind.OOXML:
        _validate_ooxml(artifact.path)
        return
    if artifact.kind == ArtifactKind.PDF:
        _validate_pdf(artifact.path)
        return
    if artifact.kind == ArtifactKind.LEGACY_OFFICE:
        from dietrich.safety.cfb import validate_cfb

        validate_cfb(artifact.path)
        return
    raise InvalidDocumentError(f"unknown candidate artifact kind: {artifact.kind}")


def _validate_ooxml(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            validate_archive_safety(archive, allow_signed=True)
            failed_member = archive.testzip()
    except zipfile.BadZipFile as exc:
        raise InvalidDocumentError(f"written package is not a valid ZIP: {exc}") from exc
    if failed_member is not None:
        raise InvalidDocumentError(f"written package failed ZIP verification at {failed_member}")


def _validate_pdf(path: Path) -> None:
    try:
        import pikepdf
    except ImportError as exc:
        from dietrich.errors import MissingDependencyError

        raise MissingDependencyError(
            "PDF validation requires: pip install 'dietrich[pdf]' (pikepdf)."
        ) from exc
    try:
        with pikepdf.open(path):
            pass
    except pikepdf.PdfError as exc:
        raise InvalidDocumentError(f"written PDF failed validation: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    """Persist the final directory entry where the platform supports it."""
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["ArtifactTransaction", "validate_candidate"]
