"""Secondary static analyses used by the HexAudit report.

These analyses produce structured evidence rather than placeholder values.

They are conservative heuristics and should never be presented as proof of
exploitability.
"""

from __future__ import annotations

import re
from typing import Any


# ============================================================================
# TAINT ANALYSIS
# ============================================================================

_SOURCE_PATTERNS = {
    "msg.sender": re.compile(
        r"\bmsg\.sender\b"
    ),
    "msg.value": re.compile(
        r"\bmsg\.value\b"
    ),
    "tx.origin": re.compile(
        r"\btx\.origin\b"
    ),
    "block.timestamp": re.compile(
        r"\bblock\.timestamp\b"
    ),
    "block.number": re.compile(
        r"\bblock\.number\b"
    ),
    "external_calldata": re.compile(
        r"\b(?:calldata|memory)\b.*"
        r"(?:address|uint|bytes|string)"
    ),
    "oracle": re.compile(
        r"\b(?:latestRoundData|"
        r"getRoundData|latestAnswer|consult|slot0)\b"
    ),
    "amm_spot": re.compile(
        r"\b(?:getReserves|reserve0|"
        r"reserve1|balanceOf)\b"
    ),
}


_SINK_PATTERNS = {
    "state_write": re.compile(
        r"\b[A-Za-z_]\w*"
        r"(?:\[[^\]]+\])*"
        r"\s*="
    ),
    "value_transfer": re.compile(
        r"\.(?:call|send|transfer)"
        r"\s*(?:\{|\()"
    ),
    "arithmetic": re.compile(
        r"\b[A-Za-z_]\w*"
        r"\s*(?:\+|-|\*|/)"
        r"\s*[A-Za-z_0-9]"
    ),
    "access_control": re.compile(
        r"\b(?:require|assert)"
        r"\s*\([^)]*"
        r"(?:msg\.sender|tx\.origin)"
    ),
    "external_call": re.compile(
        r"\.(?:call|delegatecall|staticcall)"
        r"\s*(?:\{|\()"
    ),
}


def _function_at_line(
    source: str,
    line: int,
) -> str | None:
    """Best-effort function name for evidence grouping."""

    lines = source.splitlines()

    current: str | None = None

    function_re = re.compile(
        r"\bfunction\s+([A-Za-z_]\w*)\s*\("
    )

    for index, text in enumerate(
        lines,
        start=1,
    ):
        match = function_re.search(text)

        if match:
            current = match.group(1)

        if index == line:
            return current

    return current


def build_taint_analysis(
    source: str,
) -> dict[str, Any]:
    """Build a conservative source-to-sink taint map.

    First implementation is function-scoped. A source can connect to a sink
    only when it occurs earlier in the same function.

    This is evidence generation, not proof of exploitability.
    """

    lines = source.splitlines()

    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for line_number, text in enumerate(
        lines,
        start=1,
    ):
        stripped = text.strip()

        if (
            not stripped
            or stripped.startswith("//")
        ):
            continue

        function = _function_at_line(
            source,
            line_number,
        )

        for name, pattern in _SOURCE_PATTERNS.items():
            if pattern.search(text):
                sources.append(
                    {
                        "id": f"S{len(sources) + 1}",
                        "kind": name,
                        "line": line_number,
                        "function": function,
                        "expression": stripped[:240],
                    }
                )

        for name, pattern in _SINK_PATTERNS.items():
            if pattern.search(text):
                sinks.append(
                    {
                        "id": f"K{len(sinks) + 1}",
                        "kind": name,
                        "line": line_number,
                        "function": function,
                        "expression": stripped[:240],
                    }
                )

    # Conservative same-function propagation.
    for source_node in sources:
        for sink_node in sinks:
            same_function = (
                source_node["function"] is not None
                and source_node["function"]
                == sink_node["function"]
            )

            if (
                same_function
                and source_node["line"]
                <= sink_node["line"]
            ):
                edges.append(
                    {
                        "source": source_node["id"],
                        "sink": sink_node["id"],
                        "sourceKind": source_node["kind"],
                        "sinkKind": sink_node["kind"],
                        "path": [
                            source_node["line"],
                            sink_node["line"],
                        ],
                        "confidence": 0.65,
                    }
                )

    return {
        "sources": sources,
        "sinks": sinks,
        "edges": edges,
        "sourceCount": len(sources),
        "sinkCount": len(sinks),
        "edgeCount": len(edges),
        "analysis": (
            "function-scoped conservative "
            "taint analysis"
        ),
        "limitations": [
            "Does not yet model aliases or complex expressions.",
            "Does not yet perform full interprocedural propagation.",
            (
                "Edges are evidence candidates, "
                "not proof of exploitability."
            ),
        ],
    }


# ============================================================================
# EVM BYTECODE
# ============================================================================

# Opcode names we actually care about.
_OPCODE_NAMES = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",

    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",

    0x20: "KECCAK256",

    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",

    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",

    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",

    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",

    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


def _opcode_counts(
    bytecode_hex: str,
) -> dict[str, int]:
    """Disassemble enough of EVM bytecode to count real opcodes.

    Crucially, PUSH1-PUSH32 immediate bytes are skipped and therefore cannot
    accidentally be interpreted as opcodes.
    """

    if not bytecode_hex:
        return {}

    bytecode_hex = bytecode_hex.removeprefix(
        "0x"
    )

    try:
        data = bytes.fromhex(
            bytecode_hex
        )
    except ValueError:
        return {}

    counts: dict[str, int] = {}

    program_counter = 0

    while program_counter < len(data):
        opcode = data[program_counter]

        # PUSH1 through PUSH32.
        if 0x60 <= opcode <= 0x7F:
            push_size = (
                opcode - 0x5F
            )

            program_counter += (
                1 + push_size
            )

            continue

        name = _OPCODE_NAMES.get(
            opcode
        )

        if name:
            counts[name] = (
                counts.get(name, 0) + 1
            )

        program_counter += 1

    return counts


def build_bytecode_analysis(
    creation_bytecode: str | None,
    runtime_bytecode: str | None,
) -> dict[str, Any]:
    """Return deterministic bytecode statistics and security flags."""

    creation = (
        creation_bytecode or ""
    ).removeprefix("0x")

    runtime = (
        runtime_bytecode or ""
    ).removeprefix("0x")

    runtime_counts = _opcode_counts(
        runtime
    )

    dangerous: list[dict[str, Any]] = []

    for opcode in (
        "DELEGATECALL",
        "CALLCODE",
        "SELFDESTRUCT",
        "INVALID",
    ):
        count = runtime_counts.get(
            opcode,
            0,
        )

        if count:
            dangerous.append(
                {
                    "opcode": opcode,
                    "count": count,
                    "severity": (
                        "HIGH"
                        if opcode
                        in {
                            "DELEGATECALL",
                            "CALLCODE",
                        }
                        else "CRITICAL"
                    ),
                }
            )

    return {
        "available": bool(runtime),

        "creationBytecodeLength": (
            len(creation) // 2
        ),

        "runtimeBytecodeLength": (
            len(runtime) // 2
        ),

        "runtimeOpcodes": runtime_counts,

        "dangerousOpcodes": dangerous,

        "hasDelegatecall": (
            runtime_counts.get(
                "DELEGATECALL",
                0,
            )
            > 0
        ),

        "hasCallcode": (
            runtime_counts.get(
                "CALLCODE",
                0,
            )
            > 0
        ),

        "hasSelfdestruct": (
            runtime_counts.get(
                "SELFDESTRUCT",
                0,
            )
            > 0
        ),

        "hasInvalid": (
            runtime_counts.get(
                "INVALID",
                0,
            )
            > 0
        ),
    }


# ============================================================================
# GAS HEURISTICS
# ============================================================================


def build_gas_optimizations(
    source: str,
) -> list[dict[str, Any]]:
    """Identify conservative source-level gas optimization opportunities."""

    findings: list[dict[str, Any]] = []

    lines = source.splitlines()

    for line_number, text in enumerate(
        lines,
        start=1,
    ):
        stripped = text.strip()

        if (
            not stripped
            or stripped.startswith("//")
        ):
            continue

        # Multiple explicit SLOAD mentions.
        if stripped.count("SLOAD") > 1:
            findings.append(
                {
                    "type": "REPEATED_STORAGE_READ",
                    "severity": "LOW",
                    "line": line_number,
                    "description": (
                        "Multiple storage reads appear on the same "
                        "line; cache the value in memory when safe."
                    ),
                    "estimatedSavings": (
                        "context-dependent"
                    ),
                }
            )

        # State variable packing review.
        if (
            re.search(
                r"\b(?:uint|int|address|bool|bytes\d*)\s+public\b",
                text,
            )
            and "=" in text
        ):
            findings.append(
                {
                    "type": "STATE_VARIABLE_PACKING_REVIEW",
                    "severity": "INFORMATIONAL",
                    "line": line_number,
                    "description": (
                        "Review adjacent small state variables for "
                        "storage packing opportunities."
                    ),
                    "estimatedSavings": (
                        "context-dependent"
                    ),
                }
            )

        # External calls inside loops.
        if (
            re.search(
                r"\b(?:for|while)\s*\(",
                text,
            )
            and re.search(
                r"\.(?:call|transfer|send)"
                r"\s*(?:\{|\()",
                text,
            )
        ):
            findings.append(
                {
                    "type": "EXTERNAL_CALL_IN_LOOP",
                    "severity": "MEDIUM",
                    "line": line_number,
                    "description": (
                        "An external call appears in a loop; "
                        "review gas growth and failure behavior."
                    ),
                    "estimatedSavings": (
                        "potentially significant"
                    ),
                }
            )

    # Constant / immutable opportunities.
    for line_number, text in enumerate(
        lines,
        start=1,
    ):
        if re.search(
            r"\b(?:address|uint(?:8|16|32|64|128|256)?|"
            r"bool|string)\b"
            r"\s+"
            r"(?:public|private|internal|external)?\s*"
            r"[A-Za-z_]\w*\s*="
            r"\s*[^;]+;",
            text,
        ):
            if (
                "constant" not in text
                and "immutable" not in text
            ):
                findings.append(
                    {
                        "type": "CONSTANT_IMMUTABLE_REVIEW",
                        "severity": "INFORMATIONAL",
                        "line": line_number,
                        "description": (
                            "This state variable has an initializer. "
                            "If its value never changes, consider "
                            "constant or immutable storage."
                        ),
                        "estimatedSavings": (
                            "storage-dependent"
                        ),
                    }
                )

    return findings