"""Hardened loopback HTTP adapter for Dietrich's local graphical UI."""

from __future__ import annotations

import importlib.util
import json
import secrets
import shutil
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socket import socket
from typing import Any, cast
from urllib.parse import urlsplit

from dietrich.dispatch import export_document_hash, inspect_document, unlock_document
from dietrich.gui.operations import OperationConflictError, OperationManager
from dietrich.gui.options import (
    RequestValidationError,
    build_unlock_options,
    existing_source,
    validate_create_paths,
)

MAX_JSON_BODY = 64 * 1024
MAX_DIRECTORY_ENTRIES = 500
SOCKET_TIMEOUT_SECONDS = 15

_ASSETS: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/model.js": ("model.js", "text/javascript; charset=utf-8"),
    "/browser.js": ("browser.js", "text/javascript; charset=utf-8"),
    "/pixelify-sans.ttf": ("pixelify-sans.ttf", "font/ttf"),
    "/vt323.ttf": ("vt323.ttf", "font/ttf"),
    "/locksmith-atlas.png": ("locksmith-atlas.png", "image/png"),
}


class APIError(Exception):
    """An HTTP status and safe error message for a rejected API request."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


class DietrichHTTPServer(ThreadingHTTPServer):
    """Loopback server owning a bounded asynchronous operation manager."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, initial_path: Path | None, *, port: int) -> None:
        self.session_token = secrets.token_urlsafe(32)
        startup = Path(initial_path).expanduser() if initial_path is not None else None
        self.operations = OperationManager(startup)
        self.assets_root = Path(__file__).with_name("assets")
        self._operations_closed = False
        super().__init__(("127.0.0.1", port), DietrichRequestHandler)

    def get_request(self) -> tuple[socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        return connection, address

    def close_operations(self) -> None:
        """Cancel and await the active backend operation exactly once."""
        if not self._operations_closed:
            self.operations.close()
            self._operations_closed = True

    def server_close(self) -> None:
        """Close backend operations before releasing the listening socket."""
        self.close_operations()
        super().server_close()


class DietrichRequestHandler(BaseHTTPRequestHandler):
    """Serve explicit assets and authenticated JSON requests without request logs."""

    protocol_version = "HTTP/1.1"

    @property
    def app_server(self) -> DietrichHTTPServer:
        """Return the narrowed server type installed by this handler."""
        return cast(DietrichHTTPServer, self.server)

    def log_message(self, format: str, *args: object) -> None:
        """Suppress paths, request bodies, credentials, and routine access logs."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        try:
            self._check_host()
            self._serve_asset()
        except APIError as exc:
            self._send_error(exc.status, str(exc))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        try:
            self._check_api_security()
            payload = self._read_json()
            result = self._route_api(payload)
        except APIError as exc:
            self._send_error(exc.status, str(exc))
            return
        except (RequestValidationError, ValueError) as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except FileExistsError as exc:
            self._send_error(HTTPStatus.CONFLICT, str(exc))
            return
        except OSError as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc) or "filesystem request failed")
            return
        except OperationConflictError as exc:
            self._send_error(HTTPStatus.CONFLICT, str(exc))
            return
        self._send_json(HTTPStatus.OK, result)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._send_error(HTTPStatus.FORBIDDEN, "cross-origin requests are not supported")

    def _check_host(self) -> None:
        port = self.app_server.server_address[1]
        allowed = {f"127.0.0.1:{port}"}
        if port == 80:
            allowed.add("127.0.0.1")
        if self.headers.get("Host") not in allowed:
            raise APIError(HTTPStatus.FORBIDDEN, "invalid host")

    def _check_api_security(self) -> None:
        self._check_host()
        supplied = self.headers.get("X-Dietrich-Token")
        if not isinstance(supplied, str) or not supplied.isascii():
            raise APIError(HTTPStatus.FORBIDDEN, "invalid session token")
        if not secrets.compare_digest(supplied, self.app_server.session_token):
            raise APIError(HTTPStatus.FORBIDDEN, "invalid session token")
        origin = self.headers.get("Origin")
        port = self.app_server.server_address[1]
        allowed_origins = {f"http://127.0.0.1:{port}"}
        if port == 80:
            allowed_origins.add("http://127.0.0.1")
        if origin is not None and origin not in allowed_origins:
            raise APIError(HTTPStatus.FORBIDDEN, "invalid origin")

    def _serve_asset(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment or parsed.path not in _ASSETS:
            raise APIError(HTTPStatus.NOT_FOUND, "not found")
        filename, media_type = _ASSETS[parsed.path]
        path = self.app_server.assets_root / filename
        try:
            content = path.read_bytes()
        except (FileNotFoundError, OSError):
            raise APIError(HTTPStatus.NOT_FOUND, "not found") from None
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding") is not None:
            raise APIError(HTTPStatus.BAD_REQUEST, "transfer encoding is not supported")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise APIError(HTTPStatus.BAD_REQUEST, "Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError as exc:
            raise APIError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
        if length < 0 or length > MAX_JSON_BODY:
            raise APIError(HTTPStatus.BAD_REQUEST, "JSON body size is invalid")
        try:
            decoded = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise APIError(HTTPStatus.BAD_REQUEST, "request body must be valid JSON") from exc
        if not isinstance(decoded, dict):
            raise APIError(HTTPStatus.BAD_REQUEST, "request body must be a JSON object")
        return decoded

    def _route_api(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = urlsplit(self.path)
        if path.query or path.fragment:
            raise APIError(HTTPStatus.BAD_REQUEST, "API URLs must not include a query or fragment")
        routes: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "/api/info": self._info,
            "/api/browse": self._browse,
            "/api/inspect": self._inspect,
            "/api/create": self._create,
            "/api/export": self._export,
            "/api/status": self._status,
            "/api/cancel": self._cancel,
        }
        route = routes.get(path.path)
        if route is None:
            raise APIError(HTTPStatus.BAD_REQUEST, "unknown API endpoint")
        return route(payload)

    def _info(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, set())
        selected = self.app_server.operations.last_path
        path_kind = "folder" if selected is not None and selected.is_dir() else "file"
        browse_path = (
            selected if path_kind == "folder" else selected.parent if selected is not None else None
        )
        return {
            "home": str(Path.home()),
            "path": str(selected) if selected is not None else None,
            "path_kind": path_kind if selected is not None else None,
            "browse_path": str(browse_path) if browse_path is not None else str(Path.home()),
            "dependencies": {
                "pdf": _module_available("pikepdf"),
                "crypto": _module_available("msoffcrypto"),
                "legacy": _module_available("olefile"),
                "sign": _module_available("cryptography") and _module_available("lxml"),
                "hashcat": shutil.which("hashcat") is not None,
            },
            "active_operation": self.app_server.operations.current(),
        }

    def _browse(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"path", "kind"})
        raw_path = payload["path"]
        kind = payload["kind"]
        if not isinstance(raw_path, str) or not raw_path:
            raise RequestValidationError("path must be a non-empty path string")
        if not isinstance(kind, str) or kind not in {"file", "folder"}:
            raise RequestValidationError("kind must be 'file' or 'folder'")
        selected = Path(raw_path).expanduser()
        directory = selected.parent if selected.is_file() else selected
        if not directory.is_dir():
            raise RequestValidationError("path does not identify an existing folder or file")
        entries, truncated = _directory_entries(directory, folders_only=kind == "folder")
        parent = directory.parent if directory.parent != directory else directory
        return {
            "path": str(directory),
            "parent": str(parent),
            "entries": entries,
            "truncated": truncated,
        }

    def _inspect(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"path"}, {"request_id"})
        source = existing_source(payload["path"])
        return self.app_server.operations.start(
            kind="inspect",
            path=source,
            output=None,
            request_id=_request_id(payload),
            operation=lambda control: inspect_document(source, control=control),
        )

    def _create(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"path", "output", "options"}, {"request_id"})
        options = build_unlock_options(payload["options"])
        source, target = validate_create_paths(payload["path"], payload["output"], options)
        return self.app_server.operations.start(
            kind="create",
            path=source,
            output=target,
            request_id=_request_id(payload),
            operation=lambda control: unlock_document(source, target, options, control=control),
        )

    def _export(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"path", "format"}, {"request_id"})
        source = existing_source(payload["path"])
        format_name = payload["format"]
        if not isinstance(format_name, str) or format_name not in {"hashcat", "john"}:
            raise RequestValidationError("format must be 'hashcat' or 'john'")
        return self.app_server.operations.start(
            kind="export",
            path=source,
            output=None,
            request_id=_request_id(payload),
            operation=lambda control: {
                "hash": export_document_hash(source, format_name, control=control)
            },
        )

    def _status(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"id"})
        return self.app_server.operations.status(_identifier(payload["id"]))

    def _cancel(self, payload: dict[str, Any]) -> dict[str, Any]:
        _require_keys(payload, {"id"})
        return self.app_server.operations.cancel(_identifier(payload["id"]))

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self.close_connection = True
        self._send_json(status, {"error": message})


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _require_keys(
    payload: dict[str, Any], required: set[str], optional: set[str] | None = None
) -> None:
    actual = set(payload)
    allowed = required | (optional or set())
    if not required <= actual or not actual <= allowed:
        raise RequestValidationError("request fields do not match the endpoint contract")


def _request_id(payload: dict[str, Any]) -> str | None:
    value = payload.get("request_id")
    if value is None and "request_id" not in payload:
        return None
    if not isinstance(value, str) or not value or len(value) > 128 or not value.isascii():
        raise RequestValidationError(
            "request_id must be a non-empty ASCII string of at most 128 characters"
        )
    return value


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RequestValidationError("id must be a non-empty string")
    return value


def _directory_entries(directory: Path, *, folders_only: bool) -> tuple[list[dict[str, Any]], bool]:
    candidates: list[tuple[Path, bool]] = []
    try:
        for child in directory.iterdir():
            is_directory = child.is_dir()
            if folders_only and not is_directory:
                continue
            candidates.append((child, is_directory))
            if len(candidates) > MAX_DIRECTORY_ENTRIES:
                break
    except OSError as exc:
        raise RequestValidationError("folder cannot be listed") from exc
    truncated = len(candidates) > MAX_DIRECTORY_ENTRIES
    candidates = candidates[:MAX_DIRECTORY_ENTRIES]
    candidates.sort(key=lambda item: (not item[1], item[0].name.casefold()))
    entries = [
        {"name": child.name, "path": str(child), "directory": is_directory}
        for child, is_directory in candidates
    ]
    return entries, truncated


def create_server(initial_path: Path | None = None, *, port: int = 0) -> DietrichHTTPServer:
    """Create a random-port loopback server ready for ``serve_forever``."""
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65_535:
        raise ValueError("port must be an integer between 0 and 65535")
    return DietrichHTTPServer(initial_path, port=port)


__all__ = ["DietrichHTTPServer", "create_server"]
