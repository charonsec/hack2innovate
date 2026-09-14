import { buildTaintAnalysis, TaintAnalysis } from '../src/engine/taint';
import { Parser } from '../src/engine/parser';
import { DetectorContext } from '../src/types/index';

// Contract designed to exercise all taint sink categories:
// msg.value → state_write, oracle price → price_calc, tx.origin → access_control,
// external_calldata parameter → state_write, transfer amount → .call{value:}
const source = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TaintTest {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public collateral;
    address public oracle;

    // msg.value flows directly into state mapping (state_write)
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // oracle price used in price_calc and collateral computation
    function borrow(uint256 amount) external {
        uint256 price = IOracle(oracle).getPrice();
        uint256 collateralNeeded = (amount * price) / 1e18;
        collateral[msg.sender] = collateralNeeded;
    }

    // transfer_amount: msg.value used in .call{value:}
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    // access_control: tx.origin in require
    function emergency() external {
        require(tx.origin == owner, "Not owner");
        selfdestruct(payable(tx.origin));
    }

    // external_calldata parameter propagates to state_write
    function setBalance(address user, uint256 amount) external {
        balances[user] = amount;
    }

    address public owner;
    constructor() { owner = msg.sender; }
}

interface IOracle {
    function getPrice() external view returns (uint256);
}
`;

function runTaint(): TaintAnalysis {
  const lines = source.split('\n');
  const parser = new Parser(source);
  const ast = parser.parseAstSafe()!;
  const functions = parser.extractFunctions(ast);
  const stateVariables = parser.extractStateVariables(ast);
  const context: DetectorContext = {
    sourceCode: source,
    lines,
    functions,
    stateVariables,
    solidityVersion: '0.8.0',
    usesSafeMath: false,
    usesReentrancyGuard: false,
    usesOwnable: true,
    usesAccessControl: false,
    ast,
  };
  return buildTaintAnalysis(source, ast, context);
}

function main(): void {
  const ta = runTaint();
  let pass = true;
  const check = (label: string, ok: boolean) => {
    console.log(`  ${ok ? 'PASS' : 'FAIL'} ${label}`);
    if (!ok) pass = false;
  };

  // ── Sources ───────────────────────────────────────────────────────────────
  const srcTags = ta.sources.map((s) => `${s.source}:${s.variable}`);
  console.log('=== Taint Source Verification ===');
  check('msg.value source',     srcTags.some((s) => s.includes('msg.value')));
  check('msg.sender source',    srcTags.some((s) => s.includes('msg.sender')));
  check('tx.origin source',     srcTags.some((s) => s.includes('tx.origin')));
  check('external_calldata',    srcTags.some((s) => s.includes('external_calldata')));

  // ── Sinks ─────────────────────────────────────────────────────────────────
  const sinkTypes = ta.sinks.map((s) => s.sink);
  console.log('=== Taint Sink Verification ===');
  check('state_write',      sinkTypes.includes('state_write'));
  check('access_control',   sinkTypes.includes('access_control'));
  check('transfer_amount',  sinkTypes.includes('transfer_amount'));

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('=== Summary Verification ===');
  check('msg.value → state_write',
    ta.summary.some((s) => s.includes('msg.value') && s.includes('state_write')));
  check('transfer amount in .call()',
    ta.summary.some((s) => s.includes('transfer amount')));
  check('access control check',
    ta.summary.some((s) => s.includes('access control')));

  // ── oracle price → price_calc via arithmetic ──────────────────────────────
  const hasPriceCalc = ta.sinks.some((s) => s.sink === 'price_calc');
  console.log('=== Price-Calc Verification ===');
  check('oracle price participates in price_calc arithmetic', hasPriceCalc);

  // ── Counts sanity ─────────────────────────────────────────────────────────
  console.log('=== Sanity Counts ===');
  console.log(`  sources=${ta.sources.length}  edges=${ta.edges.length}  sinks=${ta.sinks.length}  summary=${ta.summary.length}`);
  check('sources > 0', ta.sources.length > 0);
  check('sinks > 0',   ta.sinks.length > 0);

  console.log(`\n=== RESULT: ${pass ? 'ALL PASSED' : 'SOME FAILED'} ===`);
  if (!pass) process.exit(1);
}

main();
