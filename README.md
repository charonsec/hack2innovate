# 🔐 HexAudit

### Powered Smart Contract Security Auditor

**HexAudit** is an automated Solidity smart contract security auditing platform designed to identify common smart contract vulnerabilities, analyze contract structure through **AST and Control Flow Graphs**, correlate vulnerabilities with executable code paths, and generate interactive security reports with remediation guidance.

> **From source code → compilation → AST → CFG → vulnerability detection → risk scoring → remediation → interactive audit report.**

---

## 🚨 Problem Overview & Scope

### Storyline & Real-World Context

Imagine a decentralized finance (DeFi) protocol preparing to launch a high-yield Automated Market Maker (AMM) and lending pool holding more than **$50 million in Total Value Locked (TVL)**.

The protocol may contain thousands of lines of Solidity code governing:

* Token transfers
* Liquidity pools
* Lending and borrowing
* Collateral management
* Interest calculations
* Price oracles
* Administrative permissions
* External protocol integrations
* Low-level calls
* User withdrawals

A single vulnerability can allow an attacker to manipulate protocol state, drain funds, bypass authorization, or exploit external integrations.

Smart contract vulnerabilities such as:

* Reentrancy
* Integer arithmetic issues
* Unchecked external calls
* Access-control flaws
* Timestamp dependence
* Dangerous delegatecalls
* Oracle manipulation

have historically contributed to significant losses across the Web3 ecosystem.

Unlike traditional applications, blockchain transactions are generally irreversible. Once vulnerable code is deployed and exploited, recovering the affected assets may be impossible.

---

# ⚠️ Challenges With Current-Day Alternatives

Traditional smart contract security auditing presents several challenges.

### Manual Audits

Professional security audits can require:

* Specialized blockchain security expertise
* Large engineering teams
* Multiple weeks of review
* Significant financial investment
* Manual inspection of complex contract interactions

For large protocols, this can become expensive and slow.

### Existing Static Analysis Tools

Tools such as Slither and Mythril provide valuable low-level security analysis, but their output can still require substantial expertise to interpret.

Typical challenges include:

* False positives
* Difficulty understanding findings in application context
* Limited visualization
* Cryptic compiler/static-analysis output
* Difficulty connecting findings to control-flow paths
* Limited DeFi-specific reasoning
* Lack of integrated remediation workflows

HexAudit aims to provide a more accessible security workflow by combining static analysis, structural program analysis, vulnerability detection, risk scoring, and an interactive frontend.

---

# 🎯 Mission

The mission of HexAudit is to build an automated Solidity security analysis platform capable of transforming raw smart contract source code into an understandable, actionable security report.

The core pipeline is:

```text
                   Solidity Source
                         │
                         ▼
                ┌──────────────────┐
                │ Compiler / solc  │
                └────────┬─────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Solidity AST          Contract Bytecode
              │                     │
              ▼                     ▼
        AST Statistics        Bytecode Analysis
              │
              ▼
       Control Flow Graph
              │
              ▼
     Vulnerability Detection
              │
       ┌──────┴──────┐
       ▼             ▼
   Code-based     Slither-based
    heuristics      analysis
       │             │
       └──────┬──────┘
              ▼
       Finding Correlation
              │
              ▼
        Risk / CVSS Scoring
              │
              ▼
         Remediation
              │
              ▼
      Interactive Audit Report
```

---

# 🏗️ Architecture

HexAudit is organized around two primary runtime components:

```text
┌────────────────────────────────────────────────────────────┐
│                        HexAudit                             │
│                                                            │
│  ┌─────────────────────┐       ┌────────────────────────┐  │
│  │     React Frontend  │       │     Python Engine       │  │
│  │                     │       │                         │  │
│  │  Vite + React       │◄─────►│ FastAPI                 │  │
│  │  Monaco Editor      │ HTTP  │ Solidity Compiler       │  │
│  │  Audit Dashboard    │ WS    │ Slither                 │  │
│  │  CFG Visualization  │       │ AST Analysis             │  │
│  │  Finding Explorer   │       │ Vulnerability Detectors │  │
│  └─────────────────────┘       │ Risk Scoring             │  │
│                                │ Remediation               │  │
│                                └────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### Runtime Ports

| Component           |   Port | Purpose                       |
| ------------------- | -----: | ----------------------------- |
| Frontend            | `5173` | Web application               |
| Python Audit Engine | `3001` | Audit API and analysis engine |

The frontend communicates directly with the **Python audit engine**.

```text
Browser
   │
   ├── POST /api/audit ───────────────► Python Engine :3001
   │
   ├── GET /api/report/:reportId ─────► Python Engine :3001
   │
   ├── GET /api/templates ────────────► Python Engine :3001
   │
   └── WebSocket /ws ────────────────► Python Engine :3001
```

The TypeScript backend is **not part of the active smart-contract audit request path**.

---


Yes. The current section has unnecessary empty code blocks and numbering. For a README, I'd make it clean and copy-paste friendly like this:

````markdown
# Local Setup

## Requirements

Make sure the following are installed:

- Git
- Python 3.10+
- Node.js 18+
- npm

### Recommended Versions

```text
Node.js 20+
Python 3.11+
````

---

## 1. Clone the Repository

```bash
git clone <REPOSITORY_URL>
cd hack2innovate
```

---

## 2. Setup the Python Audit Engine

HexAudit uses a Python-based security analysis engine.

### Create a Virtual Environment

```bash
python3 -m venv .venv
```

### Activate the Virtual Environment

#### Linux / macOS

```bash
source .venv/bin/activate
```

#### Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

### Install Python Dependencies

```bash
pip install -r engine/requirements.txt
```

### Start the Audit Engine

From the project root:

```bash
cd engine
uvicorn auditor.api.main:app --host 127.0.0.1 --port 3009
```

The Python audit engine will be available at:

```text
http://127.0.0.1:3009
```

### Verify the Engine

Open a **second terminal** and run:

```bash
curl http://127.0.0.1:3009/api/health
```

Expected response:

```json
{
  "status": "ok",
  "engine": "python",
  "version": "1.0.0"
}
```

> Keep the Python engine terminal running while using the frontend.

---

## 3. Setup the Frontend

Open another terminal.

From the project root:

```bash
cd hack2innovate/frontend
```

Install frontend dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

The frontend will be available at:

```text
http://localhost:5173
```

Open the URL in your browser.

> Keep both terminals running:
>
> * **Python Audit Engine:** `127.0.0.1:3009`
> * **React Frontend:** `localhost:5173`

---

## 4. Start Using HexAudit

Once both services are running:

1. Open `http://localhost:5173`
2. Navigate to the Audit page.
3. Paste a Solidity smart contract.
4. Start the audit.
5. Review the detected vulnerabilities.
6. Select findings to inspect the affected source lines.
7. Explore the AST and Control Flow Graph.
8. Review risk scores and remediation recommendations.

````

### One small correction

For the jury, I would **not mention `npm run build` at all** in the local setup if they only need to evaluate the application. `npm run dev` is simpler and avoids the Monaco/Vite production-build issue we encountered.

Also, keep the **port numbers explicit** because your architecture intentionally uses:

```text
Frontend → 5173
Python Auditor → 3009
````



# ✨ Key Objectives & Functional Requirements

## 1. Solidity Source Code Parser

HexAudit compiles Solidity contracts using an appropriate installed Solidity compiler version based on the contract's pragma.

The engine extracts:

* Solidity AST
* Contract definitions
* Function definitions
* Modifier definitions
* State variables
* Expressions
* Function calls
* Assignments
* Control structures
* Source locations
* Bytecode
* Runtime bytecode

### AST Compatibility

HexAudit supports both:

**Modern Solidity AST**

```text
nodeType
nodes
```

and legacy Solidity AST formats used by older Solidity compiler versions:

```text
name
children
attributes
```

The engine normalizes these structures into statistics used by the audit report.

Example:

```json
{
  "total": 77,
  "totalNodes": 77,
  "functions": 4,
  "modifiers": 0,
  "stateVariables": 2,
  "contracts": 1
}
```

This allows older Solidity contracts to remain visible in the AST analysis layer.

---

# 2. Control Flow Graph Generation

HexAudit uses **Slither** to obtain function-level control-flow information.

The engine converts Slither's CFG representation into a frontend-friendly graph structure.

Each CFG node contains information such as:

```text
Node ID
Label
Node Type
Source Line
Children
Parents
Vulnerability Status
Vulnerability Types
```

Supported node classifications include:

* `ENTRY`
* `EXIT`
* `CONDITION`
* `STATEMENT`
* `CALL`
* `RETURN`

Example:

```text
withdraw#0
    │
    ▼
withdraw#1
    │
    ▼
withdraw#2  ← REENTRANCY
    │
    ▼
withdraw#3  ← REENTRANCY
    │
    ▼
withdraw#4
```

### Vulnerability-to-CFG Correlation

A major feature of HexAudit is correlating detector findings with CFG nodes.

If a finding occurs on a particular source line, the pipeline maps the vulnerability back to CFG nodes containing that line.

This enables the UI to:

* Highlight vulnerable CFG nodes
* Mark vulnerable execution paths
* Display vulnerability types
* Jump from graph nodes to source lines

---

# 3. Vulnerability Detection Engine

HexAudit currently implements a Python detector registry containing **seven active vulnerability families**.

## Detection Coverage

| Vulnerability                   | Status                           |
| ------------------------------- | -------------------------------- |
| Reentrancy                      | ✅ Implemented                    |
| Access Control                  | ✅ Implemented                    |
| Unchecked External Calls        | ✅ Implemented                    |
| Timestamp Dependence            | ✅ Implemented                    |
| Arithmetic Overflow / Underflow | ✅ Implemented                    |
| Dangerous Delegatecall          | ✅ Implemented                    |
| Oracle Manipulation Heuristics  | ✅ Implemented                    |
| Flash Loan Detection            | 🚧 Planned / heuristic expansion |

---

# 🔴 Reentrancy Detection

Reentrancy is one of the most important smart contract vulnerabilities.

HexAudit analyzes contracts for patterns where an external call can occur before sensitive state changes.

Conceptually:

```solidity
externalCall();

balances[msg.sender] -= amount;
```

The engine looks for suspicious combinations involving:

* External calls
* State mutations
* Function execution order
* ReentrancyGuard patterns
* Slither analysis
* Source-level heuristics

The audit report identifies:

* Vulnerability type
* Source line range
* Evidence
* Confidence
* Recommendation
* Remediation information

---

# 🔐 Access Control Detection

HexAudit checks for potentially dangerous authorization patterns.

Examples include:

### `tx.origin` Authorization

```solidity
require(tx.origin == owner);
```

This can introduce phishing-style authorization risks.

HexAudit flags suspicious use of:

```solidity
tx.origin
```

in authorization logic.

### Privileged State-Changing Functions

The engine also looks for potentially privileged setter functions that may lack appropriate access restrictions.

Examples include functions that modify:

* Ownership
* Critical configuration
* Protocol parameters
* Administrative addresses
* Security-sensitive state

---

# 📡 Unchecked External Calls

External calls can fail.

A contract that ignores a return value may incorrectly assume that an operation succeeded.

HexAudit checks low-level calls such as:

```solidity
target.call(data);
```

when the returned success value is ignored.

It also analyzes cases where a call result is captured but not properly validated.

The report provides:

* Vulnerable source location
* Evidence
* Description
* Recommendation
* Remediation guidance

---

# ⏱️ Timestamp Dependence

Smart contracts should be careful when using block timestamps in security-sensitive logic.

HexAudit identifies suspicious use of:

```solidity
block.timestamp
```

and reports potential timestamp-dependent behavior.

This is especially relevant when timestamps influence:

* Time-sensitive conditions
* Rewards
* Randomness
* Trading logic
* Expiration logic
* Security decisions

---

# ➗ Arithmetic Overflow / Underflow

HexAudit includes arithmetic vulnerability detection for Solidity code where integer operations may be unsafe.

The engine analyzes arithmetic expressions and reports potentially dangerous operations.

The analysis is particularly relevant to older Solidity versions where arithmetic operations do not automatically provide the same overflow protections as newer compiler versions.

---

# 🧩 Delegatecall Analysis

`delegatecall` executes code in the caller's storage context.

Incorrect use can expose contracts to severe security risks.

HexAudit identifies usage of:

```solidity
delegatecall(...)
```

and highlights potentially dangerous locations for further review.

---

# 🔮 Oracle Manipulation Heuristics

DeFi protocols frequently depend on price information.

HexAudit includes DeFi-specific heuristics that look for patterns associated with on-chain pricing and reserve information.

Examples include:

```solidity
balanceOf(...)
getReserves(...)
slot0(...)
```

combined with calculations involving:

* Prices
* Collateral
* Values
* Ratios
* Exchange rates

These heuristics help identify contracts that may require deeper review for oracle manipulation or spot-price dependency.

> Oracle analysis is intentionally heuristic: it identifies suspicious patterns rather than claiming that every finding represents an exploitable oracle attack.

---

# ⚡ Flash-Loan Attack Analysis

Flash loans are a major DeFi security concern because attackers can temporarily obtain very large amounts of capital without traditional collateral requirements.

HexAudit's architectural scope includes flash-loan attack-vector analysis.

Potential future heuristics include relationships between:

```text
Large temporary liquidity
        │
        ▼
Price manipulation
        │
        ▼
Protocol state manipulation
        │
        ▼
Oracle / collateral calculation
        │
        ▼
Asset extraction
```

### Current Status

The current Python detector registry does **not yet contain a dedicated flash-loan detector**.

Flash-loan analysis is therefore considered an expansion area of the DeFi detection layer rather than a completed detector family.

---

# 📊 Risk Scoring

HexAudit includes CVSS-oriented security risk calculations.

Each vulnerability can contain:

* Severity
* Confidence
* CVSS-related information
* Vulnerability type
* Source location
* Evidence
* Recommendation

The report aggregates individual findings into an overall contract risk assessment.

Conceptually:

```text
Individual Findings
        │
        ├── Severity
        ├── Confidence
        ├── Impact
        └── Evidence
        │
        ▼
Overall Risk Assessment
        │
        ▼
Audit Score
```

---

# 🛠️ Automated Remediation

HexAudit includes a remediation layer designed around established secure Solidity patterns.

The remediation system provides security guidance based on the vulnerability category.

Examples include:

### Reentrancy

Recommended pattern:

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is ReentrancyGuard {
    function withdraw(uint256 amount)
        external
        nonReentrant
    {
        // protected logic
    }
}
```

### Access Control

Secure patterns can use OpenZeppelin ownership/access-control mechanisms such as:

```solidity
onlyOwner
```

or role-based authorization.

### External Calls

The remediation guidance encourages explicit validation of call success and safer token-transfer abstractions such as OpenZeppelin's `SafeERC20` patterns where applicable.

### Randomness / Timestamp

The remediation layer can recommend safer approaches for applications where timestamp-dependent logic or pseudo-randomness creates security concerns.

---

# 🖥️ Interactive Audit Console

The frontend provides an interactive smart contract auditing interface.

The workflow begins with:

```text
Upload / Paste Solidity
          │
          ▼
      Start Audit
          │
          ▼
   Live Scan Progress
          │
          ▼
   Vulnerability Report
```

The source editor is integrated with the vulnerability results.

---

# 📝 Line-by-Line Vulnerability Highlighting

When a finding is selected, HexAudit identifies the corresponding source lines.

The user can navigate between:

```text
Finding
   ↓
Source line
   ↓
CFG node
   ↓
Evidence
   ↓
Remediation
```

This is designed to make the report understandable without requiring the user to interpret raw static-analysis output.

---

# 📋 Audit Report Dashboard

The report console provides multiple analysis sections.

Current report areas include:

* Overview
* Executive Summary
* Findings
* AST Analysis
* Control Flow
* Gas Analysis
* Risk Ratings
* Remediation
* Closing Summary
* Data Flow
* Bytecode Analysis

---

# 🧬 AST Analysis Dashboard

The AST section exposes structural information about the contract.

It reports metrics including:

```text
Total AST Nodes
Contracts
Functions
Modifiers
State Variables
Top Node Types
```

Example:

```text
AST Analysis

77 AST nodes parsed

Contracts             1
Functions             4
Modifiers             0
State Variables      2

Top Node Types
────────────────────────────
Identifier             15
ParameterList           8
ExpressionStatement     6
MemberAccess            5
VariableDeclaration     4
FunctionDefinition      4
```

---

# 🔀 Control Flow Visualization

HexAudit provides a visual CFG representation using graph visualization.

The graph allows users to understand the execution structure of functions.

Example:

```text
        ┌───────────┐
        │   ENTRY   │
        └─────┬─────┘
              │
              ▼
        ┌───────────┐
        │ STATEMENT │
        └─────┬─────┘
              │
              ▼
        ┌───────────┐
        │   CALL    │
        │   ⚠️      │
        └─────┬─────┘
              │
              ▼
        ┌───────────┐
        │  RETURN   │
        └───────────┘
```

Vulnerable nodes are marked in the interface and can be used to navigate to the relevant source line.

---

# 📄 Audit Findings

Each finding can expose information such as:

| Field              | Description                   |
| ------------------ | ----------------------------- |
| Vulnerability Type | Category of security issue    |
| Severity           | Security impact level         |
| Confidence         | Detector confidence           |
| Source Lines       | Vulnerable source range       |
| Evidence           | Why the finding was generated |
| Description        | Explanation of the issue      |
| Attack Path        | Relevant execution context    |
| Recommendation     | Suggested mitigation          |
| Remediated Code    | Available remediation output  |
| References         | Security references           |

This makes the report useful for both developers and security reviewers.

---

# 📦 Bytecode Analysis

The compilation pipeline extracts:

* Contract bytecode
* Runtime bytecode
* Solidity compiler version

This provides a foundation for bytecode-level security analysis and future deeper EVM analysis.

---

# ⚙️ Compiler Version Handling

Different Solidity contracts require different compiler versions.

HexAudit detects the Solidity version required by the contract's pragma.

For example:

```solidity
pragma solidity ^0.7.6;
```

The engine can select the corresponding installed compiler.

This is important because attempting to analyze an older contract with an incompatible modern compiler can result in compilation or analysis failures.

HexAudit therefore uses the detected compiler version when invoking the analysis pipeline.

---

# 🧪 Testing & Vulnerable Fixtures

The repository contains Solidity fixtures representing vulnerable and secure patterns.

### Vulnerable Fixtures

Examples include:

```text
AccessControlVuln.sol
DelegatecallVuln.sol
OracleVuln.sol
OverflowVuln.sol
ReentrancyVuln.sol
TimestampVuln.sol
TxOriginVuln.sol
UncheckedCallVuln.sol
```

### Secure Fixtures

Examples include:

```text
SecureAccessControl.sol
SecureArithmetic.sol
SecureCall.sol
SecureOracle.sol
SecureReentrancy.sol
```

These fixtures provide a repeatable way to test the detection engine.

---

# 📁 Project Structure

```text
hack2innovate/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── audit/
│   │   │   └── report/
│   │   ├── hooks/
│   │   ├── pages/
│   │   ├── store/
│   │   └── types/
│   │
│   ├── package.json
│   └── vite.config.*
│
├── engine/
│   │
│   ├── auditor/
│   │   ├── api/
│   │   │   └── main.py
│   │   │
│   │   ├── detectors/
│   │   │   ├── access_control.py
│   │   │   ├── delegatecall.py
│   │   │   ├── oracle.py
│   │   │   ├── overflow.py
│   │   │   ├── reentrancy.py
│   │   │   ├── timestamp.py
│   │   │   └── unchecked_call.py
│   │   │
│   │   ├── analysis.py
│   │   ├── cfg.py
│   │   ├── compile.py
│   │   ├── cvss.py
│   │   ├── pipeline.py
│   │   ├── remediation.py
│   │   └── schema.py
│   │
│   ├── scripts/
│   │   └── fetch_deps.sh
│   │
│   ├── templates/
│   │   └── demos/
│   │
│   ├── tests/
│   │   └── fixtures/
│   │
│   ├── requirements.txt
│   └── run.sh
│
└── README.md
```

---

# 🔌 Python Engine API

The Python engine exposes a FastAPI service.

## Health Check

```http
GET /api/health
```

Example:

```json
{
  "status": "ok",
  "engine": "python",
  "version": "1.0.0"
}
```

---

## Run Audit

```http
POST /api/audit
```

Request:

```json
{
  "contractName": "MyContract",
  "sourceCode": "pragma solidity ^0.8.0; ...",
  "contractAddress": null,
  "network": null
}
```

The engine:

1. Validates the request
2. Selects the Solidity compiler
3. Compiles the contract
4. Extracts AST information
5. Builds CFG information
6. Runs vulnerability detectors
7. Correlates findings with CFG nodes
8. Calculates risk information
9. Generates remediation data
10. Returns an `AuditReport`

---

# 📡 Real-Time Audit Progress

The engine exposes a WebSocket endpoint:

```text
/ws
```

The frontend can receive audit progress while the analysis is running.

Conceptually:

```text
Frontend
   │
   │ WebSocket
   ▼
Python Engine
   │
   ├── Compilation
   ├── AST Analysis
   ├── CFG Generation
   ├── Detection
   ├── Risk Analysis
   └── Remediation
   │
   ▼
Progress Events
   │
   ▼
Frontend Scan Console
```

---

# 📑 Retrieve Audit Report

```http
GET /api/report/{report_id}
```

Reports contain structured information including:

```text
Contract metadata
Compiler version
Lines of code
Overall risk score
Overall risk label
Audit score
Vulnerabilities
AST statistics
CFG
Gas optimizations
Secure template
Taint analysis
Bytecode analysis
```

---

# 🧰 Technology Stack

## Frontend

* React
* TypeScript
* Vite
* Monaco Editor
* D3-based visualization
* Interactive report components

## Backend / Analysis Engine

* Python
* FastAPI
* Uvicorn
* py-solc-x
* Slither
* Solidity Compiler (`solc`)

## Security Analysis

* Solidity AST
* Control Flow Graphs
* Source-level heuristics
* Slither analysis
* Vulnerability correlation
* CVSS-oriented risk scoring

---

# 🚀 Getting Started

## Prerequisites

Install:

* Node.js
* npm
* Python 3
* Git
* Solidity compiler dependencies required by the engine

---

# 1. Clone the Repository

```bash
git clone https://github.com/charonsec/hack2innovate.git
cd hack2innovate
```

---

# 2. Create Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

# 3. Install Python Dependencies

```bash
pip install -r engine/requirements.txt
```

---

# 4. Prepare Solidity Dependencies

If required by the analysis environment:

```bash
./engine/scripts/fetch_deps.sh
```

---

# 5. Start the Python Audit Engine

```bash
./engine/run.sh
```

The engine runs on:

```text
http://localhost:3001
```

Health check:

```text
http://localhost:3001/api/health
```

---

# 6. Start the Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on:

```text
http://localhost:5173
```

---

# 🔄 Complete Audit Workflow

A complete HexAudit scan follows this process:

```text
                    USER
                     │
                     ▼
              Solidity Source
                     │
                     ▼
          ┌────────────────────┐
          │  Frontend Editor   │
          │  Monaco            │
          └─────────┬──────────┘
                    │
                    │ POST /api/audit
                    ▼
          ┌────────────────────┐
          │ Python FastAPI     │
          │ Audit API          │
          └─────────┬──────────┘
                    │
                    ▼
          ┌────────────────────┐
          │ Compiler Selection │
          │ pragma-aware solc  │
          └─────────┬──────────┘
                    │
                    ▼
          ┌────────────────────┐
          │ Solidity Compiler  │
          └─────────┬──────────┘
                    │
             ┌──────┴───────┐
             ▼              ▼
           AST           Bytecode
             │              │
             ▼              ▼
       AST Statistics   Bytecode Analysis
             │
             ▼
          Slither
             │
             ▼
           CFG
             │
             ▼
     ┌───────────────────────┐
     │ Vulnerability Engine  │
     ├───────────────────────┤
     │ Reentrancy            │
     │ Access Control        │
     │ Unchecked Calls       │
     │ Timestamp             │
     │ Overflow              │
     │ Delegatecall          │
     │ Oracle Heuristics     │
     └───────────┬───────────┘
                 │
                 ▼
        Finding / CFG Mapping
                 │
                 ▼
          Risk Calculation
                 │
                 ▼
          Remediation Layer
                 │
                 ▼
            AuditReport
                 │
                 ▼
        ┌──────────────────┐
        │ React Dashboard  │
        ├──────────────────┤
        │ Findings         │
        │ AST              │
        │ CFG              │
        │ Risk             │
        │ Remediation      │
        │ Bytecode         │
        └──────────────────┘
```

---

# 🏆 What HexAudit Currently Covers

The current implementation covers the core requirements of the proposed security-auditing platform.

### ✅ Solidity Parsing

* Solidity compilation
* Compiler version selection based on pragma
* Modern AST compatibility
* Legacy AST compatibility
* AST node statistics
* Function counting
* State-variable counting
* Contract counting

### ✅ Control Flow Analysis

* Slither integration
* Function-level CFG generation
* Entry/exit nodes
* Statement nodes
* Call nodes
* Return nodes
* Parent/child relationships
* Vulnerability-to-CFG correlation
* Vulnerable CFG highlighting

### ✅ Vulnerability Detection

Currently implemented detector families:

* ✅ Reentrancy
* ✅ Access-control flaws
* ✅ Unchecked external calls
* ✅ Timestamp dependence
* ✅ Arithmetic overflow/underflow heuristics
* ✅ Delegatecall analysis
* ✅ Oracle manipulation heuristics

### 🚧 DeFi Expansion

Architecturally targeted:

* Flash-loan attack vectors
* More sophisticated oracle manipulation analysis
* Cross-contract DeFi reasoning
* Deeper economic attack-path analysis

A dedicated flash-loan detector is **not yet part of the current seven-detector Python registry**.

### ✅ Risk Analysis

* Finding severity
* Finding confidence
* CVSS-oriented scoring
* Overall risk score
* Overall risk label
* Audit score

### ✅ Remediation

* Vulnerability-specific recommendations
* OpenZeppelin-oriented secure patterns
* Remediation code support
* Secure template generation
* Reentrancy protection guidance
* Access-control protection guidance
* Safer external-call guidance

### ✅ Interactive Reporting

* Source code editor
* Vulnerability list
* Line-level source highlighting
* Finding details
* AST analysis
* CFG visualization
* Risk analysis
* Remediation section
* Bytecode section
* Data-flow-related reporting
* Gas optimization reporting
* Secure contract template output

### ✅ API Infrastructure

* FastAPI audit API
* Health endpoint
* Audit endpoint
* Report retrieval
* Template endpoint
* Upload endpoint
* WebSocket progress
* Demo contract endpoint

---

# 🧪 Example Vulnerability Flow

Consider a vulnerable withdrawal function:

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);

    (bool success,) = msg.sender.call{value: amount}("");

    balances[msg.sender] -= amount;
}
```

HexAudit can identify the relationship:

```text
          withdraw()
              │
              ▼
       Check user balance
              │
              ▼
       External call
              │
              │ ⚠️ External interaction
              ▼
       State modification
              │
              │ ⚠️ Reentrancy risk
              ▼
           Return
```

The report can then associate the vulnerable lines with CFG nodes and expose the issue through the dashboard.

---

# 🎯 Why HexAudit Is Different

HexAudit is not designed simply to output a list of static-analysis warnings.

Its goal is to connect multiple layers of analysis:

```text
SOURCE CODE
    │
    ▼
SEMANTIC STRUCTURE
    │
    ├── AST
    │
    └── CFG
         │
         ▼
SECURITY DETECTION
         │
         ▼
SOURCE LOCATION
         │
         ▼
RISK CONTEXT
         │
         ▼
REMEDIATION
         │
         ▼
HUMAN-READABLE REPORT
```

This allows a developer to move from:

> "There may be a vulnerability."

to:

> "This function contains a suspicious external interaction on these source lines, these CFG nodes are affected, the finding has this severity/confidence, and this is the recommended secure pattern."

---

# 🔒 Security Philosophy

HexAudit follows a defense-in-depth approach.

No single detector should be treated as proof that a contract is secure.

The platform combines:

1. Compiler information
2. AST structure
3. CFG information
4. Static-analysis results
5. Source-level heuristics
6. Vulnerability correlation
7. Risk scoring
8. Remediation guidance

Security findings should still be reviewed by qualified security professionals before production deployment.

HexAudit is an automated analysis assistant, **not a guarantee of contract security**.

---



# 🏁 Hackathon Demonstration Flow

For a live demonstration, the recommended workflow is:

### Step 1 — Open HexAudit

```text
http://localhost:5173
```

### Step 2 — Load a vulnerable Solidity contract

Use one of the included demo contracts, for example:

```text
ReentrancyVuln.sol
```

### Step 3 — Start Audit

HexAudit sends the contract directly to the Python audit engine.

### Step 4 — Show Live Progress

Demonstrate the analysis pipeline:

```text
Compilation
    ↓
AST Analysis
    ↓
CFG Generation
    ↓
Security Detection
    ↓
Risk Analysis
    ↓
Remediation
```

### Step 5 — Open Findings

Show:

* Vulnerability type
* Severity
* Confidence
* Vulnerable lines
* Evidence
* Recommendation

### Step 6 — Click the Vulnerability

The source editor jumps to the affected line.

### Step 7 — Open Control Flow

Show the vulnerable CFG nodes highlighted in the graph.

### Step 8 — Show AST

Demonstrate:

```text
AST node count
Functions
State variables
Contracts
Node types
```

### Step 9 — Show Remediation

Demonstrate the secure coding recommendation and remediation output.

### Step 10 — Show Overall Risk

Finish with the contract's:

```text
Audit Score
Risk Score
Severity Breakdown
Finding Count
```

This gives the jury a complete story:

```text
Vulnerable Contract
        ↓
Automatic Analysis
        ↓
Vulnerability Found
        ↓
Exact Source Line
        ↓
CFG Execution Context
        ↓
Risk Assessment
        ↓
Secure Remediation
```

---

# 👥 Intended Users

HexAudit is designed for:

* Smart contract developers
* DeFi developers
* Web3 startups
* Security researchers
* Blockchain auditors
* Protocol engineering teams
* Hackathon teams
* Students learning smart contract security

---

# ⚠️ Disclaimer

HexAudit is an automated security-analysis system.

Automated analysis cannot guarantee that a smart contract is secure. Detection systems may produce false positives and false negatives, especially for complex economic attacks, cross-contract interactions, upgradeable systems, and protocol-specific invariants.

Contracts managing real funds should undergo additional manual security review and appropriate testing before deployment.

---

# 📜 License

Add the project's chosen license here.

---

# 🔐 HexAudit

**Analyze. Visualize. Understand. Remediate.**

> Automated smart contract security analysis for the next generation of DeFi.
