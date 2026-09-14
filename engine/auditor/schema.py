"""Pydantic models matching frontend/src/types/index.ts EXACTLY.

Field names use camelCase to serialize 1:1 with TypeScript.
Do not rename fields without updating the frontend.
"""
from __future__ import annotations
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field, ConfigDict


def _camel(s: str) -> str:
    parts = s.split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


class _Base(BaseModel):
    model_config = ConfigDict(alias_generator=_camel, populate_by_name=True)


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

VulnType = Literal[
    "REENTRANCY", "INTEGER_OVERFLOW", "INTEGER_UNDERFLOW", "UNCHECKED_RETURN",
    "ACCESS_CONTROL", "TIMESTAMP_DEPENDENCE", "FLASH_LOAN", "ORACLE_MANIPULATION",
    "FRONT_RUNNING", "SELF_DESTRUCT", "DELEGATECALL", "UNINITIALIZED_STORAGE",
]

CfgNodeType = Literal["ENTRY", "EXIT", "CONDITION", "STATEMENT", "CALL", "RETURN"]


class AttackPathStep(_Base):
    label: str
    description: str
    node_type: Optional[str] = None
    line: Optional[int] = None


class Vulnerability(_Base):
    id: str
    type: VulnType
    severity: Severity
    title: str
    description: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0
    code_snippet: str = ""
    recommendation: str
    remediated_code: str = ""
    references: list[str] = Field(default_factory=list)
    swc_id: str
    cvss_score: float
    confidence: float = 90.0
    evidence: list[str] = Field(default_factory=list)
    attack_path: Optional[list[AttackPathStep]] = None


class CFGNode(_Base):
    id: str
    label: str
    type: CfgNodeType
    line_number: int
    children: list[str] = Field(default_factory=list)
    parents: list[str] = Field(default_factory=list)
    is_vulnerable: bool = False
    vulnerability_types: list[str] = Field(default_factory=list)


class GasOptimization(_Base):
    line: int
    description: str
    estimated_saving: str = ""
    code: str = ""
    optimized_code: str = ""


class AuditSummary(_Base):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


class AuditReport(_Base):
    report_id: str
    contract_name: str
    timestamp: str
    scan_duration: float
    lines_of_code: int
    solc_version: str
    overall_risk_score: float
    overall_risk_label: str
    audit_score: float
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    summary: AuditSummary
    cfg: list[CFGNode] = Field(default_factory=list)
    ast: dict[str, Any] = Field(default_factory=dict)
    gas_optimizations: list[GasOptimization] = Field(default_factory=list)
    secure_template: Optional[str] = None
    taint_analysis: Optional[dict] = None
    bytecode_analysis: Optional[dict] = None


class TemplateInfo(_Base):
    id: str
    name: str
    description: str
    solidity_version: str
    source_code: str


class WSPayload(_Base):
    type: Optional[str] = None
    report_id: Optional[str] = None
    stage: Optional[str] = None
    progress: Optional[float] = None
    message: Optional[str] = None
    data: Optional[Any] = None
    timestamp: Optional[str] = None