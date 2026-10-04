"""Verify distribution boundaries and smoke installed artifacts outside the checkout."""

from __future__ import annotations

import argparse
import os
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

STYLES = {"base", "chrome", "session", "dossier", "forms", "compact"}
GUI_ASSETS = {
    "index.html",
    "styles.css",
    "app.js",
    "model.js",
    "browser.js",
    "pixelify-sans.ttf",
    "vt323.ttf",
    "pixelify-OFL.txt",
    "vt323-OFL.txt",
    "locksmith-atlas.png",
    "SOURCES.md",
}
FORBIDDEN = {".impeccable", "v2", "__pycache__", "captures", "test-results", ".git"}


def check_contents(wheel: Path, source: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
    with tarfile.open(source) as archive:
        source_names = {"/".join(Path(name).parts[1:]) for name in archive.getnames()}
    for names in (wheel_names, source_names):
        assert not any(FORBIDDEN.intersection(Path(name).parts) for name in names)
    assert {f"dietrich/tui/styles/{style}.tcss" for style in STYLES} <= wheel_names
    assert {f"src/dietrich/tui/styles/{style}.tcss" for style in STYLES} <= source_names
    assert {f"dietrich/gui/assets/{asset}" for asset in GUI_ASSETS} <= wheel_names
    assert {f"src/dietrich/gui/assets/{asset}" for asset in GUI_ASSETS} <= source_names
    assert {
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "docs/ARCHITECTURE.md",
        "site/index.html",
        "site/styles.css",
        "site/script.js",
    } <= source_names
    allowed_roots = {"src", "docs", "examples", "assets", "site", "scripts"}
    allowed_files = {
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "PKG-INFO",
        ".gitignore",
    }
    assert all(
        not name or name in allowed_files or Path(name).parts[0] in allowed_roots
        for name in source_names
    )
    print("Archive boundaries, TUI stylesheets, and graphical assets verified.")


def smoke(artifact: Path, python: str) -> None:
    with tempfile.TemporaryDirectory(prefix="dietrich-installed-") as directory:
        root = Path(directory)
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        subprocess.run(
            ["uv", "venv", "--python", python, str(root / "env")], check=True, cwd=root, env=env
        )
        bin_dir = root / "env" / ("Scripts" if os.name == "nt" else "bin")
        interpreter = bin_dir / ("python.exe" if os.name == "nt" else "python")
        subprocess.run(
            ["uv", "pip", "install", "--python", str(interpreter), f"{artifact.resolve()}[full]"],
            check=True,
            cwd=root,
            env=env,
        )
        for entrypoint in ("dietrich", "dietrich-tui", "dietrich-gui", "dietrich-research"):
            subprocess.run(
                [str(bin_dir / entrypoint), "--help"],
                check=True,
                cwd=root,
                env=env,
                stdout=subprocess.DEVNULL,
            )
        code = (
            "from importlib.resources import files; "
            "import dietrich; "
            'assert "site-packages" in dietrich.__file__; '
            'styles=files("dietrich.tui").joinpath("styles"); '
            'assert len([p for p in styles.iterdir() if p.name.endswith(".tcss")]) == 6'
        )
        subprocess.run([str(interpreter), "-I", "-c", code], check=True, cwd=root, env=env)
        gui_code = """
import http.client
import json
from threading import Thread
from dietrich.gui import create_server

server = create_server()
thread = Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    connection = http.client.HTTPConnection(*server.server_address, timeout=5)
    for asset in ('', 'styles.css', 'app.js', 'model.js', 'browser.js',
                  'pixelify-sans.ttf', 'vt323.ttf', 'locksmith-atlas.png'):
        connection.request('GET', '/' + asset)
        response = connection.getresponse()
        assert response.status == 200, (asset, response.status)
        assert response.read(), asset
    connection.request('POST', '/api/info', '{}', {
        'Content-Type': 'application/json',
        'X-Dietrich-Token': server.session_token,
    })
    response = connection.getresponse()
    assert response.status == 200
    assert 'dependencies' in json.loads(response.read())
    connection.close()
finally:
    server.shutdown()
    server.server_close()
    thread.join()
"""
        subprocess.run([str(interpreter), "-I", "-c", gui_code], check=True, cwd=root, env=env)
        print(f"Installed {artifact.name}: four entry points and local GUI assets verified.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--python", default="3.12")
    args = parser.parse_args()
    wheels = list(args.directory.glob("*.whl"))
    sources = list(args.directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        parser.error("expected exactly one wheel and one source distribution")
    check_contents(wheels[0], sources[0])
    for artifact in (wheels[0], sources[0]):
        smoke(artifact, args.python)


if __name__ == "__main__":
    main()
