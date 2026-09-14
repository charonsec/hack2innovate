"""Access control detector.

Flags:
1. `tx.origin` used inside a require() → SWC-115 / 105.
2. Functions that write privileged state (`owner`, `oracle`, price sources)
   without an owner/admin modifier.
"""
from __future__ import annotations
import re
from typing import Any
from .base import Finding

_PRIVILEGED_MODIFIER_HINTS = {"onlyowner", "onlyadmin", "onlyrole", "auth", "restricted"}
_PRIVILEGED_SETTERS = re.compile(r"\b(set|update|change|upgrade|withdrawall|emergency)\w*", re.I)


def detect(slither_obj: Any, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()

    # --- Check 1: tx.origin anywhere in a require / if condition ---
    for i, line in enumerate(lines, start=1):
        if "tx.origin" in line and ("require" in line or "if" in line or "assert" in line):
            findings.append(Finding(
                type="ACCESS_CONTROL",
                line_start=i,
                line_end=i,
                description=(
                    f"`tx.origin` is used for authorization at line {i}. A malicious "
                    f"contract can trick a user into calling it, then forward the call "
                    f"to this contract; `tx.origin` will be the victim (SWC-115)."
                ),
                recommendation=(
                    "Replace `tx.origin` with `msg.sender` in all authorization checks."
                ),
                evidence=[f"Line {i}: {line.strip()}"],
                node_ids=[],
                confidence=95.0,
                references=["https://swcregistry.io/docs/SWC-115"],
            ))

    # --- Check 2: privileged setter functions without a guard ---
    if slither_obj is None:
        return findings
    for contract in slither_obj.contracts:
        for fn in contract.functions:
            if fn.view or fn.pure:
                continue
            if not _PRIVILEGED_SETTERS.search(fn.name):
                continue
            mods = {getattr(m, "name", "").lower().replace("_", "") for m in (fn.modifiers or [])}
            if mods & _PRIVILEGED_MODIFIER_HINTS:
                continue
            # does the function body touch a sensitive state var?
            touches_sensitive = False
            for node in (fn.nodes or []):
                try:
                    for sv in node.state_variables_written:
                        if any(k in sv.name.lower() for k in ("owner", "oracle", "admin", "price", "source")):
                            touches_sensitive = True
                            break
                except Exception:
                    pass
                if touches_sensitive:
                    break
            if not touches_sensitive:
                continue
            line = _first_line(fn)
            findings.append(Finding(
                type="ACCESS_CONTROL",
                line_start=line,
                line_end=line,
                description=(
                    f"`{fn.name}()` modifies a privileged state variable but is not "
                    f"protected by any access-control modifier (SWC-105). Any external "
                    f"caller can invoke it and take over the contract."
                ),
                recommendation=(
                    "Add `onlyOwner` (OpenZeppelin `Ownable`) or a role-based check "
                    "(`AccessControl`) to this function."
                ),
                evidence=[f"Function `{fn.name}()` at line {line}", "No `onlyOwner` / `onlyRole` modifier"],
                confidence=80.0,
                references=["https://swcregistry.io/docs/SWC-105"],
            ))
    return findings


def _first_line(node: Any) -> int:
    try:
        if node.source_mapping and node.source_mapping.lines:
            return node.source_mapping.lines[0]
    except Exception:
        pass
    return 0