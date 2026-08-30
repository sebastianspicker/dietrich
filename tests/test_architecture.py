"""Enforce the package dependency direction."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src" / "dietrich"

ALLOWED_DEPENDENCIES = {
    "domain": {"domain"},
    "safety": {"domain", "errors", "safety"},
    "external_tools": {"errors"},
    "crypto": {"crypto", "domain", "errors", "external_tools", "safety"},
    "ooxml": {"domain", "errors", "ooxml", "safety"},
    "pdf": {"domain", "errors", "external_tools", "pdf", "safety"},
    "legacy": {"domain", "errors", "legacy", "safety"},
    "research": {"research", "safety"},
    "application": {
        "application",
        "crypto",
        "domain",
        "errors",
        "legacy",
        "ooxml",
        "pdf",
        "safety",
    },
    "dispatch": {"application", "domain", "errors"},
    "types": {"domain"},
}
EXEMPT_ADAPTER_LAYERS = {"__init__", "__main__", "brand", "cli", "errors", "tui"}


def _source_layer(path: Path) -> str:
    relative = path.relative_to(SOURCE)
    return relative.parts[0].removesuffix(".py")


def _dietrich_imports(path: Path) -> list[str]:
    modules: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names if alias.name.startswith("dietrich"))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                modules.append("<relative import>")
            elif node.module and node.module.startswith("dietrich"):
                modules.append(node.module)
    return modules


def _target_layer(module: str) -> str:
    parts = module.split(".")
    return parts[1] if len(parts) > 1 else "__root__"


def test_core_dependency_matrix() -> None:
    """Every core package may point only at its explicit lower-level dependencies."""
    violations = []
    for path in SOURCE.rglob("*.py"):
        source_layer = _source_layer(path)
        allowed = ALLOWED_DEPENDENCIES.get(source_layer)
        if allowed is None:
            continue
        for module in _dietrich_imports(path):
            target_layer = _target_layer(module)
            if target_layer not in allowed:
                violations.append(
                    (path.relative_to(ROOT).as_posix(), source_layer, module, sorted(allowed))
                )
    assert violations == []


def test_dependency_matrix_is_closed_world() -> None:
    """A new source package must choose explicit dependencies or be named as an adapter."""
    source_layers = {_source_layer(path) for path in SOURCE.rglob("*.py")}
    assert source_layers <= set(ALLOWED_DEPENDENCIES) | EXEMPT_ADAPTER_LAYERS


def test_only_artifact_transaction_imports_publication_helpers() -> None:
    importers = []
    owner = SOURCE / "safety" / "artifact_transaction.py"
    for path in SOURCE.rglob("*.py"):
        if path in {owner, SOURCE / "safety" / "publish.py"}:
            continue
        for module in _dietrich_imports(path):
            if module == "dietrich.safety.publish":
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []


def test_only_publish_module_uses_final_publication_primitives() -> None:
    """Keep link/replace/rename publication primitives behind one module."""
    violations = []
    owner = SOURCE / "safety" / "publish.py"
    banned_os_calls = {"link", "rename", "replace"}
    for path in SOURCE.rglob("*.py"):
        if path == owner:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module_aliases: dict[str, str] = {}
        function_aliases: set[str] = set()
        path_aliases = {"Path"}
        path_variables: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"os", "shutil"}:
                        module_aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module in {"os", "shutil"}:
                for alias in node.names:
                    if alias.name in banned_os_calls | {"move"}:
                        function_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "pathlib":
                for alias in node.names:
                    if alias.name == "Path":
                        path_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.arg) and isinstance(node.annotation, ast.Name):
                if node.annotation.id in path_aliases:
                    path_variables.add(node.arg)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if isinstance(node.annotation, ast.Name) and node.annotation.id in path_aliases:
                    path_variables.add(node.target.id)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Name) and node.value.func.id in path_aliases:
                    path_variables.update(
                        target.id for target in node.targets if isinstance(target, ast.Name)
                    )
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            violation = None
            if isinstance(node.func, ast.Name) and node.func.id in function_aliases:
                violation = node.func.id
            elif isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and receiver.id in module_aliases:
                    module = module_aliases[receiver.id]
                    if (module == "os" and node.func.attr in banned_os_calls) or (
                        module == "shutil" and node.func.attr == "move"
                    ):
                        violation = node.func.attr
                is_path_receiver = isinstance(receiver, ast.Name) and receiver.id in path_variables
                is_direct_path = (
                    isinstance(receiver, ast.Call)
                    and isinstance(receiver.func, ast.Name)
                    and receiver.func.id in path_aliases
                )
                if (is_path_receiver or is_direct_path) and node.func.attr in {
                    "link_to",
                    "rename",
                    "replace",
                }:
                    violation = node.func.attr
            if violation is not None:
                violations.append((path.relative_to(ROOT).as_posix(), violation))
    assert violations == []


def test_internal_code_uses_domain_models_not_the_compatibility_facade() -> None:
    violations = []
    for path in SOURCE.rglob("*.py"):
        if path == SOURCE / "types.py":
            continue
        if "dietrich.types" in _dietrich_imports(path):
            violations.append(path.relative_to(ROOT).as_posix())
    assert violations == []
