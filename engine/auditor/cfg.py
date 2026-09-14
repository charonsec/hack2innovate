"""Extract and flatten Slither CFG into frontend CFGNode objects."""

from __future__ import annotations

from typing import Any


def _node_kind(node: Any) -> str:
    """Map a Slither CFG node to the frontend node type."""

    try:
        from slither.core.cfg.node import NodeType

        node_type = node.type

        if node_type == NodeType.ENTRYPOINT:
            return "ENTRY"

        if node_type == NodeType.END:
            return "EXIT"

        if node_type == NodeType.IF:
            return "CONDITION"

        if node_type in (
            NodeType.EXPRESSION,
            NodeType.VARIABLE,
        ):
            try:
                if any(
                    "call" in str(ir).lower()
                    for ir in (node.irs or [])
                ):
                    return "CALL"
            except Exception:
                pass

            return "STATEMENT"

        if node_type in (
            NodeType.RETURN,
            NodeType.THROW,
        ):
            return "RETURN"

    except Exception:
        pass

    return "STATEMENT"


def _safe_label(node: Any) -> str:
    """Generate a safe human-readable CFG node label."""

    try:
        expression = getattr(
            node,
            "expression",
            None,
        )

        if expression:
            text = str(expression)

            return (
                text[:120]
                + ("..." if len(text) > 120 else "")
            )

    except Exception:
        pass

    try:
        irs = getattr(
            node,
            "irs",
            None,
        )

        if irs:
            text = str(irs)

            return (
                text[:120]
                + ("..." if len(text) > 120 else "")
            )

    except Exception:
        pass

    return (
        f"node_{getattr(node, 'node_id', '?')}"
    )


def _source_line(node: Any) -> int:
    """Get the first source line represented by a Slither node."""

    try:
        mapping = node.source_mapping

        if mapping and mapping.lines:
            return int(mapping.lines[0])

    except Exception:
        pass

    return 0


def _node_id(
    function_name: str,
    node: Any,
) -> str:
    """Create a stable frontend CFG ID."""

    return (
        f"{function_name}#{node.node_id}"
    )


def build_cfg(
    slither_obj: Any,
    vulnerable_node_ids: set[int] | None = None,
    vulnerable_types: dict[int, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Return a flat list of CFG nodes.

    Every function is represented independently. Edges reference the same
    stable function-scoped node IDs used by the frontend.
    """

    if slither_obj is None:
        return []

    vulnerable_node_ids = (
        vulnerable_node_ids
        if vulnerable_node_ids is not None
        else set()
    )

    vulnerable_types = (
        vulnerable_types
        if vulnerable_types is not None
        else {}
    )

    output: list[dict[str, Any]] = []

    try:
        contracts = slither_obj.contracts
    except Exception:
        return output

    for contract in contracts:
        try:
            functions = contract.functions
        except Exception:
            continue

        for function in functions:
            nodes = getattr(
                function,
                "nodes",
                None,
            )

            if not nodes:
                continue

            function_name = getattr(
                function,
                "name",
                "unknown",
            )

            for node in nodes:
                try:
                    node_id = _node_id(
                        function_name,
                        node,
                    )

                    children = [
                        _node_id(
                            function_name,
                            child,
                        )
                        for child in (
                            getattr(
                                node,
                                "sons",
                                None,
                            )
                            or []
                        )
                    ]

                    parents = [
                        _node_id(
                            function_name,
                            parent,
                        )
                        for parent in (
                            getattr(
                                node,
                                "fathers",
                                None,
                            )
                            or []
                        )
                    ]

                    numeric_id = getattr(
                        node,
                        "node_id",
                        -1,
                    )

                    output.append(
                        {
                            "id": node_id,
                            "label": _safe_label(node),
                            "type": _node_kind(node),
                            "lineNumber": _source_line(node),
                            "children": children,
                            "parents": parents,
                            "isVulnerable": (
                                numeric_id
                                in vulnerable_node_ids
                            ),
                            "vulnerabilityTypes": (
                                vulnerable_types.get(
                                    numeric_id,
                                    [],
                                )
                            ),
                        }
                    )

                except Exception as exc:
                    print(
                        f"[CFG] failed to serialize node: {exc}"
                    )

    return output