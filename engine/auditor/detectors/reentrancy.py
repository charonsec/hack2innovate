"""Reentrancy detector.

Detects the classic Checks-Effects-Interactions violation:

    external call
        ↓
    state mutation

The detector is intentionally source-first. It handles common Solidity
patterns including mappings such as:

    balances[msg.sender] = 0;
    balances[msg.sender] -= amount;
    balances[user] += amount;

and simple state-variable assignments.

This is a heuristic detector and does not prove exploitability.
"""

from __future__ import annotations

import re
from typing import Any

from .base import Finding


# External interaction primitives.
_EXTERNAL_CALL = re.compile(
    r"""
    \.
    (?:
        call
        |delegatecall
        |staticcall
        |transfer
        |send
    )
    \s*
    (?:
        \.[A-Za-z_]\w*
        \s*
    )?
    (?:\{|\()
    """,
    re.VERBOSE,
)


# Matches common state writes:
#
#   balances[msg.sender] = 0
#   balances[msg.sender] += amount
#   balances[msg.sender] -= amount
#   totalSupply *= x
#
# The expression deliberately allows mapping/index expressions.
_STATE_WRITE = re.compile(
    r"""
    \b
    (?P<var>[A-Za-z_]\w*)
    (?:
        \s*
        \[
            [^\]]+
        \]
    )*
    \s*
    (?:
        =(?!=)
        |\+=
        |-=
        |\*=
        |/=
        |%=
        |\+\+
        |--
    )
    """,
    re.VERBOSE,
)


_GUARD = re.compile(
    r"\b(?:nonReentrant|ReentrancyGuard)\b",
    re.IGNORECASE,
)


_FUNC_START = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\("
)


# Common declarations of state variables.
_STATE_DECLARATION = re.compile(
    r"""
    ^\s*
    (?:
        uint\d*
        |int\d*
        |address
        |bool
        |bytes\d*
        |string
        |mapping\s*\([^;]+\)
        |[A-Z_][A-Za-z0-9_]*
    )
    \s+
    (?:
        public
        |private
        |internal
        |external
        |constant
        |immutable
        |payable
    )*
    \s*
    (?P<name>[A-Za-z_]\w*)
    \s*
    (?:
        =
        |;
    )
    """,
    re.VERBOSE,
)


def _strip_comments(source: str) -> str:
    source = re.sub(
        r"//.*",
        "",
        source,
    )

    source = re.sub(
        r"/\*.*?\*/",
        "",
        source,
        flags=re.DOTALL,
    )

    return source


def _state_vars(source: str) -> set[str]:
    """Extract likely state variable names.

    This is deliberately conservative. We stop considering declarations once
    the first function begins.
    """

    source = _strip_comments(source)

    state: set[str] = set()

    for line in source.splitlines():
        if _FUNC_START.search(line):
            break

        match = _STATE_DECLARATION.match(line)

        if match:
            name = match.group("name")

            if name:
                state.add(name)

    return state


def _find_function_ranges(
    source: str,
) -> list[tuple[str, int, int]]:
    """Return [(function_name, start_line, end_line)]."""

    lines = source.splitlines()

    ranges: list[tuple[str, int, int]] = []

    current_name: str | None = None
    current_start = 0
    brace_depth = 0

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        match = _FUNC_START.search(line)

        if match and current_name is None:
            current_name = match.group(1)
            current_start = line_number

            brace_depth = (
                line.count("{")
                - line.count("}")
            )

            if brace_depth <= 0:
                ranges.append(
                    (
                        current_name,
                        current_start,
                        line_number,
                    )
                )

                current_name = None

            continue

        if current_name is not None:
            brace_depth += (
                line.count("{")
                - line.count("}")
            )

            if brace_depth <= 0:
                ranges.append(
                    (
                        current_name,
                        current_start,
                        line_number,
                    )
                )

                current_name = None

    return ranges


def _state_write_name(
    line: str,
) -> str | None:
    match = _STATE_WRITE.search(line)

    if not match:
        return None

    return match.group("var")


def detect(
    slither_obj: Any,
    source: str,
) -> list[Finding]:
    """Detect external-call-before-state-update patterns."""

    findings: list[Finding] = []

    lines = source.splitlines()

    state_vars = _state_vars(source)

    function_ranges = _find_function_ranges(source)

    for function_name, start, end in function_ranges:
        body = "\n".join(
            lines[start - 1:end]
        )

        # A function with a reentrancy guard is not reported by this
        # heuristic.
        if _GUARD.search(body):
            continue

        external_call_line: int | None = None

        # Find the first external interaction.
        for line_number in range(
            start,
            end + 1,
        ):
            if _EXTERNAL_CALL.search(
                lines[line_number - 1]
            ):
                external_call_line = line_number
                break

        if external_call_line is None:
            continue

        state_write_line: int | None = None
        state_write_var: str | None = None

        # Search for state mutation AFTER the external interaction.
        for line_number in range(
            external_call_line + 1,
            end + 1,
        ):
            variable = _state_write_name(
                lines[line_number - 1]
            )

            if variable is None:
                continue

            if variable in state_vars:
                state_write_line = line_number
                state_write_var = variable
                break

        if state_write_line is None:
            continue

        snippet = "\n".join(
            lines[
                external_call_line - 1:
                state_write_line
            ]
        )

        findings.append(
            Finding(
                type="REENTRANCY",
                line_start=external_call_line,
                line_end=state_write_line,
                description=(
                    f"`{function_name}()` performs an external call "
                    f"at line {external_call_line} before updating "
                    f"state variable `{state_write_var}` at line "
                    f"{state_write_line}. An attacker-controlled "
                    f"callee may re-enter the function before the "
                    f"state update (SWC-107)."
                ),
                recommendation=(
                    "Apply Checks-Effects-Interactions: perform all "
                    "state updates before the external call. Also "
                    "consider OpenZeppelin's `nonReentrant` modifier "
                    "for externally callable functions."
                ),
                evidence=[
                    f"External call at line {external_call_line}",
                    (
                        f"State write to `{state_write_var}` "
                        f"at line {state_write_line}"
                    ),
                    (
                        f"No `nonReentrant` guard on "
                        f"`{function_name}()`"
                    ),
                ],
                confidence=90.0,
                references=[
                    "https://swcregistry.io/docs/SWC-107",
                ],
            )
        )

    return findings