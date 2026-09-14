"""Unchecked low-level call detector — source-based.

Two patterns flagged:
1. `target.call(...)` with the return value NEVER captured. (most dangerous)
2. `(bool ok, ) = target.call(...)` where `ok` is never checked with
   require/if/assert in the rest of the function.
"""
from __future__ import annotations
import re
from typing import Any
from .base import Finding

_CALL = re.compile(r"\.(call|delegatecall|staticcall)\s*[\({]")
_CAPTURE = re.compile(r"\(\s*bool\s+(\w+)\s*,")
_USE = lambda v: re.compile(rf"\b{re.escape(v)}\b")
_FUNC_START = re.compile(r"\bfunction\s+(\w+)\s*\(")


def _fn_ranges(source: str) -> list[tuple[str, int, int]]:
    lines = source.splitlines()
    out = []
    cur = None
    depth = 0
    for i, line in enumerate(lines, start=1):
        m = _FUNC_START.search(line)
        if m and cur is None:
            cur = [m.group(1), i, i]
            depth = line.count("{") - line.count("}")
            if depth <= 0:
                cur[2] = i
                out.append(tuple(cur))
                cur = None
            continue
        if cur is not None:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                cur[2] = i
                out.append(tuple(cur))
                cur = None
    return out


def detect(slither_obj: Any, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()

    for fn_name, start, end in _fn_ranges(source):
        # Track captures seen in this function so we can look ahead
        for i in range(start, end + 1):
            line = lines[i - 1]
            if not _CALL.search(line):
                continue

            # Is the return captured?
            # look back up to 2 lines to catch multi-line assignments
            window_start = max(start, i - 2)
            window = "\n".join(lines[window_start - 1:i])
            m = _CAPTURE.search(window) or _CAPTURE.search(line)
            if not m:
                # Pattern 1: bare call, no capture at all
                findings.append(_mk(i, line, "bare call — return value discarded"))
                continue

            var = m.group(1)
            # look ahead within fn for usage of `var`
            ahead = "\n".join(lines[i:end])
            if not re.search(rf"\b(require|if|assert)\b[^;]*\b{re.escape(var)}\b", ahead):
                findings.append(_mk(i, line, f"`{var}` captured but never checked"))

    # de-dup by line_start
    seen = set()
    uniq = []
    for f in findings:
        if f.line_start in seen:
            continue
        seen.add(f.line_start)
        uniq.append(f)
    return uniq


def _mk(line_no: int, line_text: str, why: str) -> Finding:
    return Finding(
        type="UNCHECKED_RETURN",
        line_start=line_no,
        line_end=line_no,
        description=(
            f"Low-level call at line {line_no}: {why}. A failed call silently "
            f"returns false without reverting, leading to inconsistent state (SWC-104)."
        ),
        recommendation=(
            "Capture the return value and check it: "
            "`(bool ok, ) = target.call(...); require(ok, \"call failed\");` "
            "or use OpenZeppelin's `Address.sendValue` / `SafeERC20`."
        ),
        evidence=[f"Line {line_no}: {line_text.strip()}"],
        confidence=90.0,
        references=["https://swcregistry.io/docs/SWC-104"],
    )