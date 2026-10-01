from __future__ import annotations
import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def _build_import_map(tree: ast.Module) -> Dict[str, Tuple[str, str, int]]:
    """Map local imported symbol name -> (module_dotted_name, imported_name, level)"""
    import_map: Dict[str, Tuple[str, str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[-1]
                import_map[local] = (alias.name, alias.name.split(".")[-1], 0)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            level = node.level or 0
            for alias in node.names:
                local = alias.asname or alias.name
                import_map[local] = (module, alias.name, level)
    return import_map


def _resolve_module_file(module_path: str, level: int, source_file: Path) -> Optional[Path]:
    base_dir = source_file.parent
    for _ in range(max(0, level - 1)):
        base_dir = base_dir.parent

    if module_path:
        rel = Path(*module_path.split("."))
        candidates = [
            base_dir / rel.with_suffix(".py"),
            base_dir / rel / "__init__.py",
            source_file.parent / rel.with_suffix(".py"),
            source_file.parent / rel / "__init__.py",
        ]
    else:
        candidates = [base_dir / "__init__.py"]

    for c in candidates:
        if c.is_file():
            return c
    return None


def _find_function_body(source: str, func_name: str) -> Optional[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            try:
                return ast.get_source_segment(source, node) or ""
            except Exception:
                return ""
    return None


def _collect_call_names(ast_node: ast.AST) -> Set[str]:
    _SKIP = {
        "print", "len", "str", "int", "float", "list", "dict", "set", "tuple", "range",
        "enumerate", "zip", "map", "filter", "sorted", "isinstance", "hasattr", "getattr",
        "setattr", "super", "type", "open", "format", "append", "extend", "update", "get",
        "items", "keys", "values", "lower", "upper", "strip", "split", "join", "replace",
        "encode", "decode", "read", "write", "close"
    }
    names: Set[str] = set()
    for node in ast.walk(ast_node):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id not in _SKIP:
            names.add(func.id)
        elif isinstance(func, ast.Attribute) and func.attr not in _SKIP:
            names.add(func.attr)
    return names


def trace_transitive_bodies(
    func_node: ast.AST,
    file_tree: ast.Module,
    source_file: str,
    max_depth: int = 3,
    max_targets: int = 10,
) -> Tuple[List[str], bool]:
    source_path = Path(source_file).resolve()
    import_map = _build_import_map(file_tree)
    all_bodies: List[str] = []
    had_unresolved = False
    visited: Set[Tuple[str, str]] = set()

    def _recurse(ast_node: ast.AST, current_file: Path, current_tree: ast.Module, depth: int) -> None:
        nonlocal had_unresolved
        if depth <= 0:
            return
        local_imports = _build_import_map(current_tree) if current_tree != file_tree else import_map
        call_names = _collect_call_names(ast_node)

        for name in list(call_names)[:max_targets]:
            if name not in local_imports:
                continue
            module_dotted, original_name, level = local_imports[name]
            visit_key = (f"{module_dotted}:{level}", original_name)
            if visit_key in visited:
                continue
            visited.add(visit_key)

            module_file = _resolve_module_file(module_dotted, level, current_file)
            if module_file is None:
                had_unresolved = True
                continue
            try:
                module_source = module_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                had_unresolved = True
                continue

            body = _find_function_body(module_source, original_name)
            if body is None:
                continue
            all_bodies.append(body)

            try:
                sub_tree = ast.parse(module_source)
                sub_func_node = next(
                    (n for n in ast.walk(sub_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == original_name),
                    None,
                )
                if sub_func_node:
                    _recurse(sub_func_node, module_file, sub_tree, depth - 1)
            except SyntaxError:
                pass

    _recurse(func_node, source_path, file_tree, max_depth)
    return all_bodies, had_unresolved
