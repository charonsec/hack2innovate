"""Solidity compilation via py-solc-x.

Compiler selection is pragma-aware. The engine never silently falls back to
an incompatible Solidity compiler because compiler semantics are security
relevant for static analysis.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import solcx


DEFAULT_SOLC = "0.8.20"
_INSTALLED: set[str] = set()

# engine/ (compile.py is at engine/auditor/compile.py)
_ENGINE_DIR = Path(__file__).resolve().parents[1]
_DEPS_DIR = _ENGINE_DIR / "deps"

# solc import remappings: source-prefix=target-path/
REMAPS = [
    f"@openzeppelin/contracts/={_DEPS_DIR / 'oz' / 'contracts'}/",
    f"@openzeppelin/={_DEPS_DIR / 'oz'}/",
    f"@chainlink/contracts/={_DEPS_DIR / 'chainlink' / 'contracts'}/",
    f"@chainlink/={_DEPS_DIR / 'chainlink'}/",
]


_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _version_tuple(version: str) -> tuple[int, int, int]:
    match = _VERSION_RE.search(version)
    if not match:
        raise ValueError(f"Invalid Solidity version: {version}")
    return tuple(int(x) for x in match.groups())


def _pragma_expression(source: str) -> str | None:
    """Return the Solidity pragma expression, e.g. '^0.8.17'."""
    match = _PRAGMA_RE.search(source)
    return match.group(1).strip() if match else None


def _satisfies(version: str, expression: str) -> bool:
    """Small Solidity pragma constraint evaluator.

    Supports the common pragma forms found in real-world contracts:
      0.8.17
      ^0.8.17
      ~0.8.17
      >=0.8.0
      >=0.8.0 <0.9.0
      >0.7.0 <=0.8.20

    Multiple whitespace-separated constraints are treated as AND.
    """

    candidate = _version_tuple(version)
    expression = expression.strip()

    # Solidity allows || alternatives.
    alternatives = [part.strip() for part in expression.split("||")]

    for alternative in alternatives:
        constraints = alternative.split()

        if not constraints:
            continue

        valid = True

        for constraint in constraints:
            match = re.fullmatch(
                r"(<=|>=|<|>|=|\^|~)?\s*(\d+)\.(\d+)(?:\.(\d+))?",
                constraint,
            )

            if not match:
                # Handle wildcard forms such as 0.8.x / 0.8.*
                wildcard = re.fullmatch(
                    r"(\d+)\.(\d+)\.(x|\*)",
                    constraint,
                    re.IGNORECASE,
                )
                if wildcard:
                    valid &= (
                        candidate[0] == int(wildcard.group(1))
                        and candidate[1] == int(wildcard.group(2))
                    )
                    continue

                valid = False
                break

            operator = match.group(1) or "="
            major = int(match.group(2))
            minor = int(match.group(3))
            patch = int(match.group(4) or 0)
            target = (major, minor, patch)

            if operator == "=":
                # For a fully specified version, exact match.
                valid &= candidate == target

            elif operator == ">":
                valid &= candidate > target

            elif operator == ">=":
                valid &= candidate >= target

            elif operator == "<":
                valid &= candidate < target

            elif operator == "<=":
                valid &= candidate <= target

            elif operator == "~":
                # ~0.8.17 means >=0.8.17 and <0.9.0.
                valid &= candidate >= target
                valid &= candidate[0] == major
                valid &= candidate[1] == minor

            elif operator == "^":
                valid &= candidate >= target

                if major > 0:
                    valid &= candidate[0] == major
                elif minor > 0:
                    valid &= candidate[0] == major
                    valid &= candidate[1] == minor
                else:
                    valid &= candidate[:2] == target[:2]

        if valid:
            return True

    return False


def _pragma_version(source: str) -> str | None:
    """Backward-compatible helper returning the first pragma version."""
    expression = _pragma_expression(source)
    if not expression:
        return None

    match = _VERSION_RE.search(expression)
    return match.group(0) if match else None


def ensure_solc(version: str) -> str:
    """Ensure a specific solc version exists."""
    if version in _INSTALLED:
        return version

    installed = {str(v) for v in solcx.get_installed_solc_versions()}

    if version not in installed:
        try:
            solcx.install_solc(version)
        except Exception as exc:
            raise RuntimeError(
                f"Unable to install Solidity compiler {version}: {exc}"
            ) from exc

    _INSTALLED.add(version)
    return version


def _installed_versions() -> list[str]:
    """Return installed compiler versions sorted newest first."""
    versions = [
        str(version)
        for version in solcx.get_installed_solc_versions()
    ]

    return sorted(
        versions,
        key=_version_tuple,
        reverse=True,
    )


def _select_solc(source: str) -> str:
    """Select the newest compiler compatible with the source pragma."""

    expression = _pragma_expression(source)

    # No pragma: retain the project's default compiler.
    if not expression:
        return ensure_solc(DEFAULT_SOLC)

    installed = _installed_versions()

    # Prefer an already-installed compatible compiler.
    for version in installed:
        if _satisfies(version, expression):
            return version

    # No compatible installed compiler. Determine a sensible target from
    # the pragma and install it.
    pragma_version = _pragma_version(source)

    if not pragma_version:
        raise RuntimeError(
            f"Unable to determine a Solidity compiler for pragma: {expression}"
        )

    major, minor, patch = _version_tuple(pragma_version)

    # For the common range-based pragmas, use the newest patch release
    # available from the corresponding major/minor family.
    if expression.startswith("^") or expression.startswith("~"):
        if major == 0 and minor == 8:
            target = "0.8.20"
        elif major == 0 and minor == 7:
            target = "0.7.6"
        elif major == 0 and minor == 6:
            target = "0.6.12"
        elif major == 0 and minor == 5:
            target = "0.5.17"
        elif major == 0 and minor == 4:
            target = "0.4.26"
        else:
            target = pragma_version
    else:
        target = pragma_version

    if not _satisfies(target, expression):
        raise RuntimeError(
            f"No compatible Solidity compiler is available for pragma "
            f"'{expression}'. Installed: {installed}"
        )

    return ensure_solc(target)


def compile_source(
    source: str,
    contract_name: str = "Contract",
) -> dict[str, Any]:
    """Compile and return AST and compilation metadata."""

    solc_version = _select_solc(source)

    # Write source to a temp file inside engine/ so relative remappings work.
    tmp_path = _ENGINE_DIR / f"_hexaudit_{contract_name}.sol"

    try:
        tmp_path.write_text(source)

        out = solcx.compile_files(
            [str(tmp_path)],
            output_values=["ast", "bin", "bin-runtime"],
            solc_version=solc_version,
            allow_paths=str(_DEPS_DIR),
            import_remappings=REMAPS,
        )

    except Exception as exc:
        raise RuntimeError(
            f"solc {solc_version} compilation failed: {exc}"
        ) from exc

    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass

    if not out:
        raise RuntimeError(
            f"solc {solc_version} produced no compilation output"
        )

    first = next(iter(out.values()))
    ast = first.get("ast", {})

    contract_names = [
        key.split(":")[-1]
        for key in out.keys()
    ]

    return {
        "ast": ast,
        "solc_version": solc_version,
        "lines_of_code": source.count("\n") + 1,
        "contract_names": contract_names,
        "bytecode": first.get("bin", ""),
        "runtime_bytecode": first.get("bin-runtime", ""),
    }


def ast_node_stats(ast: dict[str, Any]) -> dict[str, Any]:
    """Flatten both modern and legacy Solidity AST formats into statistics.

    Modern Solidity AST:
        nodeType / nodes

    Legacy Solidity AST (Solidity 0.7.x and older):
        name / children
    """

    counts: dict[str, int] = {}
    functions = 0
    modifiers = 0
    state_vars = 0
    contracts = 0

    def walk(node: Any) -> None:
        nonlocal functions, modifiers, state_vars, contracts

        if isinstance(node, dict):
            # Modern Solidity AST uses "nodeType".
            # Legacy Solidity AST uses "name".
            node_type = node.get("nodeType") or node.get("name")

            if node_type:
                counts[node_type] = counts.get(node_type, 0) + 1

                if node_type == "FunctionDefinition":
                    functions += 1

                elif node_type == "ModifierDefinition":
                    modifiers += 1

                elif node_type == "VariableDeclaration":
                    # Modern AST stores stateVariable directly.
                    # Legacy AST stores it inside "attributes".
                    is_state_variable = node.get("stateVariable") is True

                    attributes = node.get("attributes")
                    if (
                        isinstance(attributes, dict)
                        and attributes.get("stateVariable") is True
                    ):
                        is_state_variable = True

                    if is_state_variable:
                        state_vars += 1

                elif node_type == "ContractDefinition":
                    contracts += 1

            # Recursively walk every value.
            #
            # This handles:
            #   Modern AST -> nodes
            #   Legacy AST -> children
            #   Nested AST structures -> dictionaries/lists
            for value in node.values():
                walk(value)

        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(ast)

    total_nodes = sum(counts.values())

    return {
        "total": total_nodes,
        "totalNodes": total_nodes,
        "nodeTypes": counts,
        "functions": functions,
        "modifiers": modifiers,
        "stateVariables": state_vars,
        "contracts": contracts,
    }