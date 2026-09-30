"""Bounded asynchronous operation state for the graphical adapter."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from threading import Lock, Thread, current_thread
from typing import Any

from dietrich.errors import OperationCancelledError
from dietrich.operation import OperationControl


class OperationConflictError(RuntimeError):
    """An operation cannot be selected or started in the current session state."""


class OperationManager:
    """Own at most one current operation and its cooperative control."""

    def __init__(self, initial_path: Path | None) -> None:
        self._lock = Lock()
        self._operation: dict[str, Any] | None = None
        self._control: OperationControl | None = None
        self._thread: Thread | None = None
        self._closed = False
        self._last_path = initial_path

    @property
    def last_path(self) -> Path | None:
        with self._lock:
            return self._last_path

    def start(
        self,
        *,
        kind: str,
        path: Path,
        output: Path | None,
        request_id: str | None,
        operation: Callable[[OperationControl], object],
    ) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise OperationConflictError("the graphical session is closing")
            if (
                request_id is not None
                and self._operation is not None
                and self._operation["request_id"] == request_id
            ):
                raise OperationConflictError("request_id was already accepted")
            if self._operation is not None and self._operation["status"] == "running":
                raise OperationConflictError("another operation is already running")
            identifier = secrets.token_urlsafe(18)
            control = OperationControl()
            record: dict[str, Any] = {
                "id": identifier,
                "kind": kind,
                "status": "running",
                "phase": "pending",
                "path": str(path),
                "output": str(output) if output is not None else None,
                "request_id": request_id,
                "result": None,
                "error": None,
            }
            thread = Thread(
                target=self._run,
                args=(identifier, control, operation),
                name=f"dietrich-gui-{kind}",
                daemon=False,
            )
            prior_state = self._operation, self._control, self._thread, self._last_path
            self._operation = record
            self._control = control
            self._thread = thread
            self._last_path = path
            try:
                thread.start()
            except Exception:
                self._operation, self._control, self._thread, self._last_path = prior_state
                raise
            return self._snapshot_locked()

    def _run(
        self,
        identifier: str,
        control: OperationControl,
        operation: Callable[[OperationControl], object],
    ) -> None:
        try:
            result = operation(control)
        except OperationCancelledError as exc:
            status, serialized, error = "cancelled", None, str(exc)
        except Exception as exc:  # controller boundary: surface backend failure asynchronously
            status, serialized, error = "failed", None, str(exc) or type(exc).__name__
        else:
            status, serialized, error = "completed", json_value(result), None
        with self._lock:
            if self._operation is not None and self._operation["id"] == identifier:
                self._operation.update(
                    status=status,
                    phase=control.phase,
                    result=serialized,
                    error=error,
                )

    def status(self, identifier: str) -> dict[str, Any]:
        with self._lock:
            self._require_identifier(identifier)
            return self._snapshot_locked()

    def current(self) -> dict[str, Any] | None:
        with self._lock:
            if self._operation is None:
                return None
            return self._snapshot_locked()

    def cancel(self, identifier: str) -> dict[str, Any]:
        with self._lock:
            self._require_identifier(identifier)
            assert self._operation is not None
            if self._operation["status"] != "running" or self._control is None:
                return self._snapshot_locked()
            self._control.cancel()
            return self._snapshot_locked()

    def close(self) -> None:
        with self._lock:
            if self._closed and (self._thread is None or not self._thread.is_alive()):
                return
            self._closed = True
            control = self._control
            thread = self._thread
        if control is not None:
            control.cancel()
        if thread is not None and thread is not current_thread():
            thread.join()

    def _snapshot_locked(self) -> dict[str, Any]:
        assert self._operation is not None
        record = dict(self._operation)
        control = self._control
        if record["status"] == "running" and control is not None:
            record["phase"] = control.phase
        record["cancellable"] = record["status"] == "running" and record["phase"] not in {
            "cancelling",
            "publishing",
        }
        return record

    def _require_identifier(self, identifier: str) -> None:
        if self._operation is None or not secrets.compare_digest(self._operation["id"], identifier):
            raise OperationConflictError("operation id does not match the current operation")


def json_value(value: object) -> Any:
    """Serialize domain dataclasses without ever disclosing password_used."""
    if is_dataclass(value) and not isinstance(value, type):
        return {
            key: json_value(item) for key, item in asdict(value).items() if key != "password_used"
        }
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items() if key != "password_used"}
    if isinstance(value, (tuple, list)):
        return [json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


__all__ = ["OperationConflictError", "OperationManager", "json_value"]
