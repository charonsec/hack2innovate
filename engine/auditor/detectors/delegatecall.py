"""Delegatecall to user-supplied / variable target detector."""
from __future__ import annotations
import re
from typing import Any
from .base import Finding

_DELEGATECALL = re.compile(r"\.delegatecall\s*\(")
_LITERAL = re.compile(r"0x[0-9a-fA-F]{40}")


def detect(slither_obj: Any, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        if not _DELEGATECALL.search(line):
            continue
        # if the target is a hardcoded address literal, less dangerous
        if _LITERAL.search(line) and not re.search(r"\b(address|target)\b", line):
            continue
        findings.append(Finding(
            type="DELEGATECALL",
            line_start=i,
            line_end=i,
            description=(
                f"`delegatecall` at line {i} executes arbitrary code in this "
                f"contract's storage context. If the target is user-controlled, "
                f"the caller can overwrite any storage slot including `owner` (SWC-112)."
            ),
            recommendation=(
                "Only delegatecall to trusted, immutable implementation addresses. "
                "Use OpenZeppelin's `Proxy` / `UUPSUpgradeable` with admin controls."
            ),
            evidence=[f"Line {i}: {line.strip()}"],
            confidence=88.0,
            references=["https://swcregistry.io/docs/SWC-112"],
        ))
    return findings