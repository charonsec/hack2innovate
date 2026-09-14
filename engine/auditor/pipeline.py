"""Pipeline: compile → slither → detect → analyze → remediate → AuditReport."""
from __future__ import annotations

import logging

logging.getLogger("CryticCompile").setLevel(logging.ERROR)
logging.getLogger("slither").setLevel(logging.ERROR)

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .compile import (
    compile_source,
    ast_node_stats,
    _select_solc,
    _ENGINE_DIR,
    REMAPS,
)
from .cvss import (
    cvss_for,
    severity_for,
    swc_for,
    title_for,
    risk_score,
    audit_score,
)
from .cfg import build_cfg
from .detectors import ALL as DETECTORS
from .detectors.base import Finding
from .remediation import remediation_for, secure_template
from .schema import (
    AuditReport,
    AuditSummary,
    Vulnerability,
    CFGNode,
)
from .analysis import (
    build_bytecode_analysis,
    build_gas_optimizations,
    build_taint_analysis,
)
import solcx

Progress = Callable[[str, float, str, dict | None], None]


def _noop(
    stage: str,
    progress: float,
    message: str,
    data: dict | None = None,
) -> None:
    """Default progress callback."""
    pass


def run_audit(
    contract_name: str,
    source_code: str,
    on_progress: Progress | None = None,
) -> AuditReport:
    """Run the complete HexAudit analysis pipeline."""

    on_progress = on_progress or _noop
    started = time.time()

    # ========================================================================
    # 1. COMPILATION
    # ========================================================================

    on_progress(
        "PARSING",
        5.0,
        "Compiling with solc...",
        None,
    )

    compile_result = compile_source(
        source_code,
        contract_name=contract_name,
    )

    ast = compile_result["ast"]
    solc_version = compile_result["solc_version"]
    loc = compile_result["lines_of_code"]

    on_progress(
        "PARSING",
        20.0,
        f"solc {solc_version} OK — {loc} lines",
        None,
    )

    # ========================================================================
    # 2. AST ANALYSIS
    # ========================================================================

    ast_stats = ast_node_stats(ast)

    # ========================================================================
    # 3. SECONDARY STATIC ANALYSIS
    # ========================================================================

    on_progress(
        "ANALYSIS",
        25.0,
        "Running secondary static analyses...",
        None,
    )

    # Taint analysis
    taint_analysis = build_taint_analysis(
        source_code,
    )

    # Bytecode analysis
    bytecode_analysis = build_bytecode_analysis(
        compile_result.get("bytecode"),
        compile_result.get("runtime_bytecode"),
    )

    # Gas optimization heuristics
    gas_optimizations = build_gas_optimizations(
        source_code,
    )

    # ========================================================================
    # 4. SLITHER + CFG
    # ========================================================================

    on_progress(
        "CFG_BUILD",
        30.0,
        "Building control-flow graph...",
        None,
    )

    slither_obj = None
    cfg_nodes: list[dict] = []

    try:
        from slither import Slither

        tmp_path = _ENGINE_DIR / f"_hexaudit_{contract_name}.sol"

        tmp_path.write_text(
            source_code,
            encoding="utf-8",
        )

        try:
            slither_version = _select_solc(source_code)

            solcx_install_dir = Path(solcx.get_solcx_install_folder())
            slither_solc = solcx_install_dir / f"solc-v{slither_version}"

            slither_obj = Slither(
                str(tmp_path),
                solc=str(slither_solc),
                solc_remaps=REMAPS,
            )

            cfg_nodes = build_cfg(
                slither_obj,
            )

        finally:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    except Exception as e:
        on_progress(
            "CFG_BUILD",
            35.0,
            f"Slither unavailable: {e}",
            None,
        )

    # ========================================================================
    # 5. VULNERABILITY DETECTION
    # ========================================================================

    on_progress(
        "DETECTING",
        50.0,
        "Running detectors...",
        None,
    )

    raw_findings: list[Finding] = []

    for det in DETECTORS:
        try:
            found = det.detect(
                slither_obj,
                source_code,
            )

            if found:
                raw_findings.extend(found)

        except Exception as e:
            print(
                f"[detector {det.__name__}] error: {e}"
            )

    # ========================================================================
    # 6. REMEDIATION
    # ========================================================================

    on_progress(
        "REMEDIATING",
        75.0,
        f"{len(raw_findings)} raw findings",
        None,
    )

    # ========================================================================
    # 7. CONVERT FINDINGS → VULNERABILITIES
    # ========================================================================

    vulnerabilities: list[Vulnerability] = []

    source_lines = source_code.splitlines()

    for i, finding in enumerate(
        raw_findings,
        start=1,
    ):
        snippet = _snippet(
            source_lines,
            finding.line_start,
            finding.line_end,
        )

        vulnerabilities.append(
            Vulnerability(
                id=f"HEX-{i:03d}",
                type=finding.type,
                severity=severity_for(
                    finding.type,
                ),
                title=title_for(
                    finding.type,
                ),
                description=finding.description,
                line_start=finding.line_start,
                line_end=finding.line_end,
                code_snippet=snippet,
                recommendation=finding.recommendation,
                remediated_code=(
                    finding.remediated_code
                    or remediation_for(
                        finding.type,
                    )
                ),
                references=finding.references,
                swc_id=swc_for(
                    finding.type,
                ),
                cvss_score=cvss_for(
                    finding.type,
                ),
                confidence=finding.confidence,
                evidence=finding.evidence,
                attack_path=None,
            )
        )

    # ========================================================================
    # 8. MARK VULNERABLE CFG NODES
    # ========================================================================

    # Primary correlation is source-line based because the current detectors
    # report vulnerable source ranges rather than Slither node IDs.
    #
    # We also retain node_ids as a secondary correlation mechanism for any
    # detector that eventually provides them.

    vulnerable_lines: dict[int, set[str]] = {}

    for finding in raw_findings:
        for line in range(
            finding.line_start,
            finding.line_end + 1,
        ):
            vulnerable_lines.setdefault(
                line,
                set(),
            ).add(finding.type)

    # Optional Slither node-id correlation for detectors that provide node_ids.
    vuln_node_ids: set[int] = set()

    vuln_types_by_node: dict[int, set[str]] = {}

    for finding in raw_findings:
        for node_id in finding.node_ids:
            vuln_node_ids.add(node_id)

            vuln_types_by_node.setdefault(
                node_id,
                set(),
            ).add(finding.type)

    cfg_models: list[CFGNode] = []

    for node in cfg_nodes:
        line_number = node.get("lineNumber", 0)

        # Match by source line.
        matched_types = set(
            vulnerable_lines.get(
                line_number,
                set(),
            )
        )

        # Also support explicit Slither node IDs when available.
        node_id_string = node.get("id", "")

        try:
            numeric_id = int(
                node_id_string.split("#")[-1]
            )
        except (ValueError, TypeError):
            numeric_id = -1

        matched_types.update(
            vuln_types_by_node.get(
                numeric_id,
                set(),
            )
        )

        node["isVulnerable"] = bool(
            matched_types
        )

        node["vulnerabilityTypes"] = sorted(
            matched_types
        )

        try:
            cfg_models.append(
                CFGNode(**node)
            )
        except Exception as e:
            print(
                f"[CFG] failed to build CFGNode "
                f"{node_id_string}: {e}"
            )


    # ========================================================================
    # 9. SUMMARY
    # ========================================================================

    summary = AuditSummary(
        critical=sum(
            1
            for vulnerability in vulnerabilities
            if vulnerability.severity == "CRITICAL"
        ),
        high=sum(
            1
            for vulnerability in vulnerabilities
            if vulnerability.severity == "HIGH"
        ),
        medium=sum(
            1
            for vulnerability in vulnerabilities
            if vulnerability.severity == "MEDIUM"
        ),
        low=sum(
            1
            for vulnerability in vulnerabilities
            if vulnerability.severity == "LOW"
        ),
        informational=sum(
            1
            for vulnerability in vulnerabilities
            if vulnerability.severity == "INFORMATIONAL"
        ),
        total=len(vulnerabilities),
    )

    # ========================================================================
    # 10. RISK + AUDIT SCORE
    # ========================================================================

    risk, label = risk_score(
        [
            _Sev(vulnerability.severity)
            for vulnerability in vulnerabilities
        ]
    )

    audit = audit_score(
        [
            _Sev(vulnerability.severity)
            for vulnerability in vulnerabilities
        ]
    )

    # ========================================================================
    # 11. COMPLETE
    # ========================================================================

    on_progress(
        "COMPLETE",
        100.0,
        "Audit complete.",
        None,
    )

    # ========================================================================
    # 12. FINAL REPORT
    # ========================================================================

    return AuditReport(
        report_id=str(
            uuid.uuid4()
        ),

        contract_name=contract_name,

        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),

        scan_duration=round(
            time.time() - started,
            2,
        ),

        lines_of_code=loc,

        solc_version=solc_version,

        overall_risk_score=round(
            risk,
            1,
        ),

        overall_risk_label=label,

        audit_score=audit,

        vulnerabilities=vulnerabilities,

        summary=summary,

        cfg=cfg_models,

        ast=ast_stats,

        gas_optimizations=gas_optimizations,

        secure_template=secure_template(
            source_code,
            raw_findings,
        ),

        taint_analysis=taint_analysis,

        bytecode_analysis=bytecode_analysis,
    )


class _Sev:
    """Small adapter used by the scoring functions."""

    __slots__ = ("severity",)

    def __init__(self, severity: str):
        self.severity = severity


def _snippet(
    lines: list[str],
    start: int,
    end: int,
) -> str:
    """Return source lines corresponding to a finding."""

    if start < 1 or end < start:
        return ""

    start_index = max(
        0,
        start - 1,
    )

    end_index = min(
        len(lines),
        end,
    )

    return "\n".join(
        lines[start_index:end_index]
    )