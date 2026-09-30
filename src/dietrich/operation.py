"""Cooperative operation cancellation and the atomic publication boundary."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock

from dietrich.errors import OperationCancelledError


class OperationControl:
    """Thread-safe, single-operation control. Native calls finish before checkpoints."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._phase = "pending"
        self._cancelled = False
        self._publishing = False
        self._finished = False
        self._started = False

    @property
    def phase(self) -> str:
        with self._lock:
            return self._phase

    @property
    def cancellation_requested(self) -> bool:
        with self._lock:
            return self._cancelled

    def cancel(self) -> bool:
        """Accept cancellation unless publication or completion already started."""
        with self._lock:
            if self._publishing or self._finished:
                return False
            self._cancelled = True
            self._phase = "cancelling"
            return True

    def checkpoint(self, phase: str | None = None) -> None:
        with self._lock:
            if self._cancelled:
                raise OperationCancelledError("Operation cancelled; no output was published.")
            if phase is not None and not self._publishing and not self._finished:
                self._phase = phase

    def begin_publication(self) -> None:
        """Serialize publication entry with cancellation acceptance."""
        with self._lock:
            if self._cancelled:
                raise OperationCancelledError("Operation cancelled; no output was published.")
            self._publishing = True
            self._phase = "publishing"

    def _start(self) -> None:
        with self._lock:
            if self._started:
                raise ValueError("OperationControl is single-use; create one for each operation.")
            self._started = True

    def _finish(self, phase: str) -> None:
        with self._lock:
            # Successful read-only operations also serialize completion with cancel().
            if phase == "completed" and self._cancelled:
                self._finished = True
                self._phase = "cancelled"
                raise OperationCancelledError("Operation cancelled; no output was published.")
            self._finished = True
            self._phase = phase


_CURRENT: ContextVar[OperationControl | None] = ContextVar("dietrich_operation", default=None)


def current_control() -> OperationControl | None:
    """Return control for the current synchronous use case or copied thread context."""
    return _CURRENT.get()


def checkpoint(phase: str | None = None) -> None:
    """Check the active operation, doing nothing for uncontrolled internal calls."""
    control = current_control()
    if control is not None:
        control.checkpoint(phase)


@contextmanager
def operation_scope(control: OperationControl | None = None) -> Iterator[None]:
    """Bind one public operation; nested internal scopes share its control."""
    if control is None and current_control() is not None:
        checkpoint()
        yield
        return
    owned = control or OperationControl()
    owned._start()
    token = _CURRENT.set(owned)
    try:
        owned.checkpoint("starting")
        yield
    except OperationCancelledError:
        owned._finish("cancelled")
        raise
    except BaseException:
        owned._finish("failed")
        raise
    else:
        owned._finish("completed")
    finally:
        _CURRENT.reset(token)


__all__ = ["OperationControl", "checkpoint", "current_control", "operation_scope"]
