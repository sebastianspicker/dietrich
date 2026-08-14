"""Unit coverage for the atomic output publication boundary."""

from __future__ import annotations

from pathlib import Path

from dietrich.safety.publish import publish_output, temporary_output_path


def test_temporary_output_path_is_adjacent_and_cleans_unpublished_file(tmp_path: Path) -> None:
    target = tmp_path / "result.bin"

    with temporary_output_path(target) as temp_path:
        assert temp_path.parent == target.parent
        assert temp_path.name.startswith(f".{target.name}.")
        temp_path.write_bytes(b"candidate")

    assert not temp_path.exists()
    assert not target.exists()


def test_temporary_output_path_tolerates_atomic_publish_consuming_file(tmp_path: Path) -> None:
    target = tmp_path / "result.bin"

    with temporary_output_path(target) as temp_path:
        temp_path.write_bytes(b"candidate")
        publish_output(temp_path, target, overwrite=False)

    assert target.read_bytes() == b"candidate"
    assert not temp_path.exists()
