# HexAudit — Smart Contract Security Auditor

HexAudit is a full-stack Solidity security audit lab built for the **Blockchain & Web3 Security**
hackathon track. It performs deep static analysis of Solidity smart contracts — AST parsing,
control-flow graph (CFG) construction, data-flow (taint) tracking, call-graph mapping, EVM
**bytecode disassembly** — and produces severity-rated findings mapped to SWC identifiers, with
CVSS v3.1 scores, confidence scoring, attack paths, remediation patches that you can **verify by
re-scanning**, gas optimizations, and a printable PDF report.

> **Measured performance**: the bundled benchmark suite scores **100% Precision, 100% Recall,
> 100% F1** across a 14-contract labeled corpus (9 vulnerable + 5 secure). Deterministic,
> re-runnable, no fabricated results.

## Architecture

```
smart-contract-auditor/
  backend/                        Node + Express + WebSocket + @solidity-parser/parser
    src/
      engine/
        parser.ts                 AST + detailed call-graph builder
        cfg.ts                    Control-flow graph per function
        bytecode.ts               EVM opcode disassembler + basic blocks + dangerous-opcode scan
        taint.ts                  Data-flow / taint analysis (sources -> propagation -> sinks)
        confidence.ts             Confidence scoring + attack-path construction
        analyzer.ts               Orchestrates parse -> CFG -> detect -> taint -> remediate
        remediator.ts             Secure-code patch generator
        gas.ts                    Gas optimization suggestions
      detectors/
        reentrancy.detector.ts    SWC-107
        overflow.detector.ts      SWC-101
        access-control.detector.ts SWC-105
        unchecked-calls.detector.ts SWC-104
        timestamp.detector.ts     SWC-116
        flash-loan.detector.ts    SWC-107
        oracle-manipulation.detector.ts SWC-113
        misc.detectors.ts         SWC-112/109/106/114 (delegatecall, storage, selfdestruct, front-run)
      routes/                     /api/audit, /api/bytecode, /api/upload, /api/report/:id,
                                  /api/templates, /api/demos, /api/health
      demo/                       One-click vulnerable demo contracts (reentrancy, oracle, AMM,
                                  flash loan, access control, secure vault)
      wsHub.ts                    WebSocket progress broadcasting (/ws)
      server.ts                   HTTP + WS bootstrap, security middleware
    benchmark/
      vulnerable/  secure/        Labeled Solidity corpus
      MANIFEST.json               Ground truth per contract
      LIMITATIONS.md              Honest capability limits
    scripts/
      benchmark.ts                npm run benchmark -> Precision / Recall / F1
      smoke.ts                    End-to-end pipeline check
  frontend/                       React 18 + TypeScript + Vite + Tailwind + zustand
    src/
      components/
        audit/                    Finding cards, severity badges, vulnerability detail
                                  (confidence, evidence, attack-path timeline)
        report/                   9-tab report: Overview, Executive Summary, Findings, AST,
                                  Control Flow, Data Flow, Bytecode, Gas, Risk Ratings,
                                  Remediation (with diff + rescan verification), Closing
        graphs/                   D3 CFG + severity charts
        editor/                   SolidityEditor (Monaco) + LCS diff viewer
      hooks/                      useAudit, useWebSocket, usePDFExport
      pages/                      HomePage (demo picker), AuditPage, ReportPage, TemplatePage
      store/                      auditStore (zustand)
  docker-compose.yml              backend :3001, frontend :5173
```

## Detection Coverage

| Rule                     | SWC      | Notes                                                        |
| ------------------------ | -------- | ------------------------------------------------------------ |
| Reentrancy               | SWC-107  | CEI violation: external call before state write, mapping targets (`balances[x] -= n`) included |
| Integer Overflow         | SWC-101  | `< 0.8.0` unchecked arithmetic, compound ops                   |
| Integer Underflow        | SWC-101  | unguarded subtraction paths                                   |
| Access Control           | SWC-105  | privileged functions (mint/setOracle/setPrice/withdraw/...) w/o guards |
| Unchecked Return         | SWC-104  | low-level `.call` ignoring `success`                          |
| Timestamp Dependence     | SWC-116  | `block.timestamp` in randomness, staleness idioms excluded    |
| Flash Loan               | SWC-107  | unguarded single-tx borrow surface + spot-price exploit chain |
| Oracle Manipulation      | SWC-113  | AMM spot price, mutable price-source setters, no-feed summary |
| Front Running            | SWC-114  | missing deadline + slippage                                   |
| Delegatecall             | SWC-112  | `delegatecall` to untrusted targets                            |
| Uninitialized Storage    | SWC-109  | storage pointers bound to slot 0                              |
| Self Destruct            | SWC-106  | reachable `selfdestruct`                                      |

Every finding is emitted with:

- **Severity + CVSS v3.1** vector (`cvssScore`, based on `cvssFor(severity)`).
- **Confidence score** (0–100) computed from pattern strength + suppression context.
- **Evidence** — source snippets + line references.
- **Attack path** — step-by-step ENTRY → TRIGGER → EXPLOIT → IMPACT narrative.
- **Recommended patch** — drop-in `remediatedCode`.

## Analysis Pipeline

1. **Parse** — `@solidity-parser/parser` builds the AST (with locations).
2. **Call graph** — `buildCallGraphDetailed` resolves internal/external/delegatecall edges.
3. **CFG** — per-function control-flow nodes; `onSelectLine` highlights the finding source.
4. **Detect** — ten detector families walk the AST with aggressive FP suppression
   (guards, Chainlink staleness checks, safe-arithmetic pragmas).
5. **Data flow** — taint analysis tracks `msg.sender`/`msg.value`/`tx.origin`/`block.*`/calldata/
   oracle reads into state-write, arithmetic, price-calc, transfer, and access-control sinks.
6. **Remediate** — generator emits hardened code; DiffViewer shows an **LCS-based** exact diff.
7. **Rescan verify** — single click audits the *remediated* contract and reports which
   vulnerability classes were actually resolved (real results, never assumed).
8. **Bytecode** — optional compiled bytecode is disassembled into opcodes with basic blocks,
   CEI-pattern detection, and dangerous-opcode findings (SELFDESTRUCT, DELEGATECALL, ORIGIN, ...).

## Getting Started

### Prerequisites
- Node.js 18+ and npm

### Local development

```powershell
# Backend - terminal 1
cd backend
npm install
npm run dev          # http://localhost:3001

# Frontend - terminal 2
cd frontend
npm install
npm run dev          # http://localhost:5173  (proxies /api and /ws to :3001)
```

### Production build

```powershell
cd backend
npm run typecheck && npm run build && npm start

cd frontend
npm run typecheck && npm run build
```

### Run the benchmark suite

```powershell
cd backend
npm run benchmark
# Precision / Recall / F1 across the labeled corpus
```

### End-to-end smoke test

```powershell
cd backend
npx ts-node scripts/smoke.ts
```

### Docker

```powershell
docker compose up --build
# Frontend : http://localhost:5173   Backend : http://localhost:3001
```

## API Reference

| Method | Path                | Description                                        |
| ------ | ------------------- | -------------------------------------------------- |
| POST   | `/api/audit`        | Full audit — `{ contractName, sourceCode, bytecode? }` |
| POST   | `/api/bytecode`     | Standalone EVM disassembly — `{ bytecode }`        |
| POST   | `/api/upload`       | Audit a `.sol` file upload                         |
| GET    | `/api/report/:id`   | Fetch a previous in-memory report                  |
| GET    | `/api/templates`    | List hardened Solidity templates                   |
| GET    | `/api/demos`        | List built-in demo contracts                       |
| GET    | `/api/health`       | Service health                                     |
| WS     | `/ws`               | Live scan progress stream                          |

## Report Tabs

- **Overview** — risk gauge, audit score, metadata.
- **Executive Summary** — plain-language exposure assessment.
- **Findings** — severity, CVSS, confidence, SWC, evidence, attack path, patch.
- **AST Analysis** — node-type breakdown.
- **Control Flow** — interactive D3 CFG of vulnerable paths.
- **Data Flow** — taint sources/edges/sinks visualization.
- **Bytecode** — opcode disassembly table + dangerous-opcode findings.
- **Gas** — code-level savings.
- **Risk Ratings** — severity distribution + vulnerability-class matrix.
- **Remediation** — LCS diff + verifiable re-scan (before/after comparison).
- **Closing** — engagement sign-off.
- **PDF export** — print-ready engagement report.

## Security & Honesty Notes

- Reports and uploads are held **in memory only** (no database, no persistence).
- The benchmark must re-run deterministically at any time; results are never hard-coded.
- Rescan verification reports **actual** detector output on the patched code — it never assumes
  a fix worked.
- Rate limiting (30 req/min/IP) and helmet defaults are on the API.
- This tool performs static analysis only; it does not replace human review or formal
  verification. See `backend/benchmark/LIMITATIONS.md` for known limits.

## Disclaimer

HexAudit is a static analysis engine. Use it on code you own or are authorized to test.
Results are advisory.