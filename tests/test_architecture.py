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
BANNED_OS_CALLS = {"link", "rename", "replace"}
BANNED_PATH_CALLS = {"link_to", "rename", "replace"}


class _PublicationReferences(ast.NodeVisitor):
    """Collect the aliases and path variables needed by the publication rule."""

    def __init__(self) -> None:
        self.module_aliases: dict[str, str] = {}
        self.function_aliases: set[str] = set()
        self.path_aliases = {"Path"}
        self.path_variables: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in {"os", "shutil"}:
                self.module_aliases[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in {"os", "shutil"}:
            self._add_function_aliases(node.names)
        elif node.module == "pathlib":
            self._add_path_aliases(node.names)

    def visit_arg(self, node: ast.arg) -> None:
        if _annotation_name(node.annotation) in self.path_aliases:
            self.path_variables.add(node.arg)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and (
            _annotation_name(node.annotation) in self.path_aliases
        ):
            self.path_variables.add(node.target.id)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if _constructor_name(node.value) in self.path_aliases:
            self.path_variables.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
        self.generic_visit(node)

    def _add_function_aliases(self, aliases: list[ast.alias]) -> None:
        for alias in aliases:
            if alias.name in BANNED_OS_CALLS | {"move"}:
                self.function_aliases.add(alias.asname or alias.name)

    def _add_path_aliases(self, aliases: list[ast.alias]) -> None:
        for alias in aliases:
            if alias.name == "Path":
                self.path_aliases.add(alias.asname or alias.name)


def _source_layer(path: Path) -> str:
    relative = path.relative_to(SOURCE)
    return relative.parts[0].removesuffix(".py")


def _dietrich_imports(path: Path) -> list[str]:
    modules: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules.extend(_imported_dietrich_modules(node))
    return modules


def _imported_dietrich_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names if alias.name.startswith("dietrich")]
    if not isinstance(node, ast.ImportFrom):
        return []
    if node.level:
        return ["<relative import>"]
    if node.module and node.module.startswith("dietrich"):
        return [node.module]
    return []


def _annotation_name(annotation: ast.expr | None) -> str | None:
    return annotation.id if isinstance(annotation, ast.Name) else None


def _constructor_name(expression: ast.expr) -> str | None:
    if not isinstance(expression, ast.Call) or not isinstance(expression.func, ast.Name):
        return None
    return expression.func.id


def _publication_violation(
    call: ast.Call,
    references: _PublicationReferences,
) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id if call.func.id in references.function_aliases else None
    if not isinstance(call.func, ast.Attribute):
        return None
    return _attribute_publication_violation(call.func, references)


def _attribute_publication_violation(
    attribute: ast.Attribute,
    references: _PublicationReferences,
) -> str | None:
    module_violation = _module_publication_violation(attribute, references.module_aliases)
    if module_violation is not None:
        return module_violation
    if _is_path_receiver(attribute.value, references) and attribute.attr in BANNED_PATH_CALLS:
        return attribute.attr
    return None


def _module_publication_violation(
    attribute: ast.Attribute,
    module_aliases: dict[str, str],
) -> str | None:
    if not isinstance(attribute.value, ast.Name):
        return None
    module = module_aliases.get(attribute.value.id)
    if module == "os" and attribute.attr in BANNED_OS_CALLS:
        return attribute.attr
    if module == "shutil" and attribute.attr == "move":
        return attribute.attr
    return None


def _is_path_receiver(
    receiver: ast.expr,
    references: _PublicationReferences,
) -> bool:
    if isinstance(receiver, ast.Name):
        return receiver.id in references.path_variables
    return _constructor_name(receiver) in references.path_aliases


def _publication_violations(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    references = _PublicationReferences()
    references.visit(tree)
    relative_path = path.relative_to(ROOT).as_posix()
    return [
        (relative_path, violation)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        if (violation := _publication_violation(node, references)) is not None
    ]


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
    for path in SOURCE.rglob("*.py"):
        if path == owner:
            continue
        violations.extend(_publication_violations(path))
    assert violations == []


def test_internal_code_uses_domain_models_not_the_compatibility_facade() -> None:
    violations = []
    for path in SOURCE.rglob("*.py"):
        if path == SOURCE / "types.py":
            continue
        if "dietrich.types" in _dietrich_imports(path):
            violations.append(path.relative_to(ROOT).as_posix())
    assert violations == []
