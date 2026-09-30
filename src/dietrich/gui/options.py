"""Strict JSON-to-domain validation for the graphical adapter."""

from __future__ import annotations

import os
from dataclasses import fields
from pathlib import Path
from typing import Any

from dietrich.domain.models import UnlockOptions

_BOOL_FIELDS = {
    "remove_worksheet_protection",
    "remove_workbook_protection",
    "remove_document_protection",
    "remove_modify_verifier",
    "remove_mark_as_final",
    "strip_pdf_permissions",
    "strip_signatures",
    "unlock_vba",
    "soft_only",
    "overwrite",
    "use_hashcat",
}
_OPTIONAL_STRING_FIELDS = {"password", "mask", "charset"}
_PATH_FIELDS = {"wordlist", "resign_cert", "resign_key"}
_OPTIONAL_POSITIVE_INT_FIELDS = {"max_length", "hashcat_timeout"}
_POSITIVE_INT_FIELDS = {"max_candidates", "workers"}


class RequestValidationError(ValueError):
    """A safe, user-facing request validation failure."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def build_unlock_options(value: object) -> UnlockOptions:
    """Validate an exact UnlockOptions-shaped JSON object and preserve its values."""
    if not isinstance(value, dict):
        raise RequestValidationError("options must be a JSON object")
    known = {field.name for field in fields(UnlockOptions)}
    unknown = set(value) - known
    if unknown:
        raise RequestValidationError(f"unknown option: {sorted(unknown)[0]}")

    converted: dict[str, Any] = {}
    for name, raw in value.items():
        if name in _BOOL_FIELDS:
            if type(raw) is not bool:
                raise RequestValidationError(f"{name} must be a boolean")
            converted[name] = raw
        elif name in _OPTIONAL_STRING_FIELDS:
            if raw is not None and not isinstance(raw, str):
                raise RequestValidationError(f"{name} must be a string or null")
            converted[name] = raw
        elif name in _PATH_FIELDS:
            converted[name] = _existing_file_option(name, raw)
        elif name in _OPTIONAL_POSITIVE_INT_FIELDS:
            if raw is not None and (not _is_int(raw) or raw <= 0):
                raise RequestValidationError(f"{name} must be a positive integer or null")
            converted[name] = raw
        elif name in _POSITIVE_INT_FIELDS:
            if not _is_int(raw) or raw <= 0:
                raise RequestValidationError(f"{name} must be a positive integer")
            converted[name] = raw
        elif name == "hashcat_args":
            if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
                raise RequestValidationError("hashcat_args must be an array of strings")
            converted[name] = tuple(raw)
        else:  # pragma: no cover - guarded by the dataclass field inventory
            raise RequestValidationError(f"unsupported option: {name}")

    options = UnlockOptions(**converted)
    if (options.resign_cert is None) ^ (options.resign_key is None):
        raise RequestValidationError("resign_cert and resign_key must be provided together")
    if options.use_hashcat and not (options.wordlist or options.mask or options.hashcat_args):
        raise RequestValidationError(
            "use_hashcat requires wordlist, mask, or at least one hashcat_args value"
        )
    return options


def _existing_file_option(name: str, raw: object) -> Path | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw:
        raise RequestValidationError(f"{name} must be a non-empty path string or null")
    path = Path(raw).expanduser()
    if not path.is_file():
        raise RequestValidationError(f"{name} does not identify an existing file")
    return path


def validate_create_paths(
    path: object, output: object, options: UnlockOptions
) -> tuple[Path, Path]:
    """Validate source/output identity, suffix, parent, and collision policy."""
    source = existing_source(path)
    if not isinstance(output, str) or not output:
        raise RequestValidationError("output must be a non-empty path string")
    target = Path(output).expanduser()
    if source.suffix.lower() != target.suffix.lower():
        raise RequestValidationError("output suffix must match the source suffix")
    if not target.parent.is_dir():
        raise RequestValidationError("output parent folder does not exist")
    if _same_file(source, target):
        raise RequestValidationError("source and output must identify different files")
    if target.exists() and not target.is_file():
        raise RequestValidationError("output must identify a file")
    if target.exists() and not options.overwrite:
        raise FileExistsError("output already exists; enable overwrite to replace it")
    return source, target


def existing_source(value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise RequestValidationError("path must be a non-empty path string")
    path = Path(value).expanduser()
    if not path.is_file():
        raise RequestValidationError("path does not identify an existing file")
    return path


def _same_file(source: Path, target: Path) -> bool:
    try:
        return os.path.samefile(source, target)
    except FileNotFoundError:
        try:
            return source.resolve(strict=True) == target.resolve(strict=False)
        except RuntimeError as exc:
            raise RequestValidationError("source or output path cannot be resolved") from exc


def assert_unlock_options_inventory() -> None:
    """Fail loudly in development if the public options model gains an unvalidated field."""
    handled = (
        _BOOL_FIELDS
        | _OPTIONAL_STRING_FIELDS
        | _PATH_FIELDS
        | _OPTIONAL_POSITIVE_INT_FIELDS
        | _POSITIVE_INT_FIELDS
        | {"hashcat_args"}
    )
    model = {field.name for field in fields(UnlockOptions)}
    if handled != model:
        raise RuntimeError("GUI UnlockOptions validation is out of sync with the domain model")


assert_unlock_options_inventory()

__all__ = [
    "RequestValidationError",
    "build_unlock_options",
    "existing_source",
    "validate_create_paths",
]
