# HexAudit — Smart Contract Security Auditor

HexAudit is a full-stack Solidity security audit lab: a Node.js/Express + WebSocket detection
engine in the backend and a rich React + TypeScript workspace in the frontend. It parses Solidity
into an abstract syntax tree (AST), builds a control-flow graph (CFG), and runs ten detection
families mapped to SWC identifiers — producing severity-rated findings, CVSS v3.1 scores,
remediation patches, gas optimizations, a secure contract template, and a PDF report.

## Architecture

```
smart-contract-auditor/
├── backend/                 Node 18 + Express 4 + ws + @solidity-parser/parser
│   ├── src/
│   │   ├── engine/          parser → cfg → analyzer → remediator → gas
│   │   ├── detectors/       7 detectors + misc (front-running, delegatecall, storage)
│   │   ├── routes/          POST /api/audit · POST /api/upload · GET /api/report/:id
│   │   │                    GET /api/templates · GET /api/health
│   │   ├── wsHub.ts         WebSocket progress broadcasting (/ws)
│   │   ├── server.ts        HTTP + WS bootstrap, security middleware
│   │   └── templates/       secure-erc20.sol · secure-lending.sol · secure-amm.sol
│   └── scripts/smoke.ts     CLI end-to-end pipeline check
├── frontend/                React 18 + TypeScript + Vite + Tailwind + zustand
│   └── src/
│       ├── components/      ui · layout · editor · audit · graphs · report
│       ├── hooks/           useWebSocket · useAudit · usePDFExport
│       ├── pages/           HomePage · AuditPage · ReportPage · TemplatePage
│       ├── store/           auditStore (zustand)
│       └── utils/           severity · format · highlight
└── docker-compose.yml       backend :3001 · frontend (nginx) :5173
```

## Detection Coverage

| Rule                    | SWC      | Notes                                            |
| ----------------------- | -------- | ------------------------------------------------ |
| Reentrancy              | SWC-107  | Checks-Effects-Interactions gap over external calls |
| Integer Overflow        | SWC-101  | division-by-zero + `< 0.8` unchecked arithmetic    |
| Integer Underflow       | SWC-101  | unguarded subtraction paths                       |
| Access Control          | SWC-105  | privileged functions without guards               |
| Unchecked Return        | SWC-104  | low-level calls ignoring `success`                |
| Timestamp Dependence    | SWC-116  | `block.timestamp` in randomness/fairness          |
| Flash Loan              | SWC-107  | unguarded single-transaction borrow surface       |
| Oracle Manipulation     | SWC-113  | spot/`slot0` pricing                              |
| Front Running           | SWC-114  | missing deadline + slippage                       |
| Delegatecall            | SWC-112  | `delegatecall` with untrusted targets             |
| Uninitialized Storage   | SWC-109  | storage pointers bound to slot 0                  |
| Self Destruct           | SWC-106  | reachable `selfdestruct`                          |

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- (Optional) Docker + Docker Compose

### Local development

```powershell
# Backend — terminal 1
cd backend
npm install
npm run dev          # http://localhost:3001

# Frontend — terminal 2
cd frontend
npm install
npm run dev          # http://localhost:5173  (proxies /api and /ws to :3001)
```

### Production build & smoke test

```powershell
cd backend
npm run typecheck && npm run build
npm start

cd frontend
npm run typecheck && npm run build
```

The engine smoke test (`backend/scripts/smoke.ts`) runs the full pipeline against a
`VulnerableDeFiPool` contract and prints findings, CFG node count, risk score, and gas savings:

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

| Method | Path                | Description                              |
| ------ | ------------------- | ---------------------------------------- |
| POST   | `/api/audit`        | Run a full audit (JSON: contractName, sourceCode, optional contractAddress/network) |
| POST   | `/api/upload`       | Audit a `.sol` file upload               |
| GET    | `/api/report/:id`   | Fetch a previous in-memory report        |
| GET    | `/api/templates`    | List hardened Solidity templates         |
| GET    | `/api/health`       | Service health                           |
| WS     | `/ws`               | Live scan progress stream                |

## Audit Report

Every audit produces:

- **Overview** — risk gauge, audit score, metadata.
- **Executive Summary** — plain-language exposure assessment.
- **Findings** — severity, CVSS v3.1, SWC reference, vulnerable snippet, remediated patch.
- **AST Analysis** — node-type breakdown + contract statistics.
- **Control Flow Graph** — interactive D3 visualization of vulnerable execution paths.
- **Gas Optimizations** — code-level cost savings.
- **Risk Ratings** — severity distribution + vulnerability-class matrix.
- **Remediation** — diff view + downloadable hardened template.
- **PDF export** — print-ready `.pdf` of the full engagement.

## Security Notes

- Reports and uploads are held **in memory only** (no database, no persistence).
- Rate limiting (30 req/min/IP) and helmet defaults are enabled on the API.
- This tool performs static analysis only; it does not substitute for human review or
  formal verification.

## Disclaimer

HexAudit is a static analysis engine. Use it on code you own or are authorized to test.
Results are advisory.