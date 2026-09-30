"""Pure background-operation helpers for the Dietrich Textual controller.

The functions in this module perform the blocking document calls and normalize
the exceptions that the TUI can display.  They deliberately have no Textual
imports: :mod:`dietrich.tui.app` owns worker scheduling, widget updates, and
marshalling results back to the UI thread.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

from dietrich.dispatch import export_document_hash, inspect_document, unlock_document
from dietrich.domain.models import DocumentInspection, UnlockOptions, UnlockResult
from dietrich.errors import DietrichError, OperationCancelledError
from dietrich.operation import OperationControl

_Value = TypeVar("_Value")


@dataclass(frozen=True)
class TaskFailure:
    """An operation failure normalized for TUI presentation."""

    message: str
    unexpected: bool = False
    cancelled: bool = False

    @property
    def display_message(self) -> str:
        """Return the shared inspect/unlock wording for this failure."""
        return f"unexpected: {self.message}" if self.unexpected else self.message


@dataclass(frozen=True)
class TaskResult(Generic[_Value]):
    """A blocking document-operation result or normalized failure."""

    value: _Value | None = None
    failure: TaskFailure | None = None

    @classmethod
    def success(cls, value: _Value) -> TaskResult[_Value]:
        """Build a successful task result."""
        return cls(value=value)

    @classmethod
    def failed(cls, failure: TaskFailure) -> TaskResult[_Value]:
        """Build a failed task result."""
        return cls(failure=failure)

    def require_value(self) -> _Value:
        """Return the successful value or reject an invalid result state."""
        if self.value is None:
            raise RuntimeError("Task completed without a value or failure.")
        return self.value


def inspect_task(
    path: Path,
    *,
    inspect: Callable[..., DocumentInspection] = inspect_document,
    control: OperationControl | None = None,
) -> TaskResult[DocumentInspection]:
    """Inspect ``path`` and map expected failures for the TUI."""
    return _run_task(
        lambda: inspect(path, control=control) if control is not None else inspect(path)
    )


def unlock_task(
    source: Path,
    target: Path,
    options: UnlockOptions,
    *,
    unlock: Callable[..., UnlockResult] = unlock_document,
    control: OperationControl | None = None,
) -> TaskResult[UnlockResult]:
    """Unlock a document and map expected failures for the TUI."""
    return _run_task(
        lambda: (
            unlock(source, target, options, control=control)
            if control is not None
            else unlock(source, target, options)
        )
    )


def export_hash_task(
    path: Path,
    *,
    export: Callable[..., str] = export_document_hash,
    control: OperationControl | None = None,
) -> TaskResult[str]:
    """Export a hashcat line and map expected failures for the TUI."""
    return _run_task(
        lambda: (
            export(path, "hashcat", control=control)
            if control is not None
            else export(path, "hashcat")
        )
    )


def export_hash_message(result: TaskResult[str]) -> str:
    """Format an export operation outcome with the established log wording."""
    if result.failure is not None:
        prefix = "export-hash unexpected" if result.failure.unexpected else "export-hash error"
        return f"{prefix}: {result.failure.message}"
    if result.value is None:
        raise RuntimeError("Export hash task completed without a value or failure.")
    display = result.value if len(result.value) <= 160 else result.value[:140] + "…"
    return f"hashcat line: {display}"


def _run_task(operation: Callable[[], _Value]) -> TaskResult[_Value]:
    """Run one operation using the worker error contract already exposed by the TUI."""
    try:
        return TaskResult.success(operation())
    except OperationCancelledError as exc:
        return TaskResult.failed(TaskFailure(str(exc), cancelled=True))
    except DietrichError as exc:
        return TaskResult.failed(TaskFailure(str(exc)))
    # This is the controller boundary: every library/vendor failure must become
    # a result so the UI thread can always clear its busy state.
    except Exception as exc:
        return TaskResult.failed(TaskFailure(str(exc), unexpected=True))
