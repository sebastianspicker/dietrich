"""Command-line launcher for Dietrich's local graphical adapter."""

from __future__ import annotations

import argparse
import webbrowser
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

from dietrich.gui.server import create_server


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dietrich-gui",
        description="Open Dietrich's local graphical document workbench.",
    )
    parser.add_argument("path", nargs="?", type=Path, help="Document or folder to show initially")
    parser.add_argument("--port", type=_port, default=0, help="Loopback port (default: random)")
    parser.add_argument(
        "--no-browser", action="store_true", help="Print the private URL without opening a browser"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the GUI until interrupted, then await backend cleanup."""
    args = _parser().parse_args(argv)
    server = create_server(args.path, port=args.port)
    host = str(server.server_address[0])
    port = int(server.server_address[1])
    base_url = f"http://{host}:{port}/"
    private_url = f"{base_url}#token={quote(server.session_token, safe='')}"
    print(f"Dietrich GUI: {private_url}")
    try:
        if not args.no_browser:
            webbrowser.open(private_url)
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
