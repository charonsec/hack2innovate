export interface BytecodeOp {
  pc: number;
  opcode: string;
  mnemonic: string;
  args: number[];
  isPush: boolean;
  isDangerous: boolean;
  danger?: string;
}

export interface BytecodeFinding {
  opcode: string;
  pc: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
}

export interface BasicBlock {
  start: number;
  end: number;
  ops: string[];
  summary: string;
}

export interface BytecodeAnalysis {
  valid: boolean;
  bytecodeLength: number;
  error?: string;
  instructionCount: number;
  pushconstantCount: number;
  opcodes: BytecodeOp[];
  findings: BytecodeFinding[];
  hasDelegatecall: boolean;
  hasSelfdestruct: boolean;
  hasSstore: boolean;
  hasCallValue: boolean;
  basicBlocks: BasicBlock[];
}

interface OpcodeEntry {
  name: string;
  mnemonic: string;
  pushBytes: number;
}

const OPCODE_TABLE: Record<number, OpcodeEntry> = {};

function reg(code: number, name: string, mnemonic: string, pushBytes = 0): void {
  OPCODE_TABLE[code] = { name, mnemonic, pushBytes };
}

// 0x00 – 0x0f: Arithmetic
reg(0x00, 'STOP', 'STOP');
reg(0x01, 'ADD', 'ADD');
reg(0x02, 'MUL', 'MUL');
reg(0x03, 'SUB', 'SUB');
reg(0x04, 'DIV', 'DIV');
reg(0x05, 'SDIV', 'SDIV');
reg(0x06, 'MOD', 'MOD');
reg(0x07, 'SMOD', 'SMOD');
reg(0x08, 'ADDMOD', 'ADDMOD');
reg(0x09, 'MULMOD', 'MULMOD');
reg(0x0a, 'EXP', 'EXP');
reg(0x0b, 'SIGNEXTEND', 'SIGNEXTEND');

// 0x10 – 0x1f: Comparison & Bitwise
reg(0x10, 'LT', 'LT');
reg(0x11, 'GT', 'GT');
reg(0x12, 'SLT', 'SLT');
reg(0x13, 'SGT', 'SGT');
reg(0x14, 'EQ', 'EQ');
reg(0x15, 'ISZERO', 'ISZERO');
reg(0x16, 'AND', 'AND');
reg(0x17, 'OR', 'OR');
reg(0x18, 'XOR', 'XOR');
reg(0x19, 'NOT', 'NOT');
reg(0x1a, 'BYTE', 'BYTE');
reg(0x1b, 'SHL', 'SHL');
reg(0x1c, 'SHR', 'SHR');
reg(0x1d, 'SAR', 'SAR');
reg(0x1e, 'SHA3', 'KECCAK256');

// 0x20: KECCAK256 alias already set above; skip duplicate

// 0x30 – 0x4f: Environment & Block
reg(0x30, 'ADDRESS', 'ADDRESS');
reg(0x31, 'BALANCE', 'BALANCE');
reg(0x32, 'ORIGIN', 'ORIGIN');
reg(0x33, 'CALLER', 'CALLER');
reg(0x34, 'CALLVALUE', 'CALLVALUE');
reg(0x35, 'CALLDATALOAD', 'CALLDATALOAD');
reg(0x36, 'CALLDATASIZE', 'CALLDATASIZE');
reg(0x37, 'CALLDATACOPY', 'CALLDATACOPY');
reg(0x38, 'CODESIZE', 'CODESIZE');
reg(0x39, 'CODECOPY', 'CODECOPY');
reg(0x3a, 'GASPRICE', 'GASPRICE');
reg(0x3b, 'EXTCODESIZE', 'EXTCODESIZE');
reg(0x3c, 'EXTCODECOPY', 'EXTCODECOPY');
reg(0x3d, 'RETURNDATASIZE', 'RETURNDATASIZE');
reg(0x3e, 'RETURNDATACOPY', 'RETURNDATACOPY');
reg(0x3f, 'EXTCODEHASH', 'EXTCODEHASH');
reg(0x40, 'BLOCKHASH', 'BLOCKHASH');
reg(0x41, 'COINBASE', 'COINBASE');
reg(0x42, 'TIMESTAMP', 'TIMESTAMP');
reg(0x43, 'NUMBER', 'NUMBER');
reg(0x44, 'DIFFICULTY', 'PREVRANDAO');
reg(0x45, 'GASLIMIT', 'GASLIMIT');
reg(0x46, 'CHAINID', 'CHAINID');
reg(0x47, 'SELFBALANCE', 'SELFBALANCE');
reg(0x48, 'BASEFEE', 'BASEFEE');
reg(0x49, 'BLOBHASH', 'BLOBHASH');
reg(0x4a, 'BLOBBASEFEE', 'BLOBBASEFEE');

// 0x50 – 0x5f: Stack, Memory, Storage, Flow
reg(0x50, 'POP', 'POP');
reg(0x51, 'MLOAD', 'MLOAD');
reg(0x52, 'MSTORE', 'MSTORE');
reg(0x53, 'MSTORE8', 'MSTORE8');
reg(0x54, 'SLOAD', 'SLOAD');
reg(0x55, 'SSTORE', 'SSTORE');
reg(0x56, 'JUMP', 'JUMP');
reg(0x57, 'JUMPI', 'JUMPI');
reg(0x58, 'PC', 'PC');
reg(0x59, 'MSIZE', 'MSIZE');
reg(0x5a, 'GAS', 'GAS');
reg(0x5b, 'JUMPDEST', 'JUMPDEST');
reg(0x5c, 'TLOAD', 'TLOAD');
reg(0x5d, 'TSTORE', 'TSTORE');
reg(0x5e, 'MCOPY', 'MCOPY');

// 0x5f: PUSH0
reg(0x5f, 'PUSH0', 'PUSH0', 0);

// 0x60 – 0x7f: PUSH1 – PUSH32
for (let i = 0; i < 32; i++) {
  reg(0x60 + i, `PUSH${i + 1}`, `PUSH${i + 1}`, i + 1);
}

// 0x80 – 0x8f: DUP1 – DUP16
for (let i = 0; i < 16; i++) {
  reg(0x80 + i, `DUP${i + 1}`, `DUP${i + 1}`);
}

// 0x90 – 0x9f: SWAP1 – SWAP16
for (let i = 0; i < 16; i++) {
  reg(0x90 + i, `SWAP${i + 1}`, `SWAP${i + 1}`);
}

// 0xa0 – 0xa4: LOG0 – LOG4
for (let i = 0; i < 5; i++) {
  reg(0xa0 + i, `LOG${i}`, `LOG${i}`);
}

// 0xf0 – 0xff: System
reg(0xf0, 'CREATE', 'CREATE');
reg(0xf1, 'CALL', 'CALL');
reg(0xf2, 'CALLCODE', 'CALLCODE');
reg(0xf3, 'RETURN', 'RETURN');
reg(0xf4, 'DELEGATECALL', 'DELEGATECALL');
reg(0xf5, 'CREATE2', 'CREATE2');
reg(0xfa, 'STATICCALL', 'STATICCALL');
reg(0xfd, 'REVERT', 'REVERT');
reg(0xfe, 'INVALID', 'INVALID');
reg(0xff, 'SELFDESTRUCT', 'SELFDESTRUCT');

// Dangerous opcode metadata
const DANGEROUS: Record<number, { severity: BytecodeFinding['severity']; title: string; description: string }> = {
  0xff: { severity: 'CRITICAL', title: 'Unprotected SELFDESTRUCT', description: 'Unprotected selfdestruct reachable — allows contract destruction and fund drainage' },
  0xf4: { severity: 'HIGH', title: 'DELEGATECALL usage', description: 'Delegatecall executes code in the context of this contract\'s storage — proxy / storage-collision risk' },
  0x55: { severity: 'MEDIUM', title: 'SSTORE (state write)', description: 'State write — storage slot mutation' },
  0xf1: { severity: 'MEDIUM', title: 'External CALL', description: 'External call — reentrancy surface' },
  0x34: { severity: 'MEDIUM', title: 'CALLVALUE read', description: 'msg.value read — payable handling required' },
  0x32: { severity: 'HIGH', title: 'ORIGIN used (tx.origin)', description: 'tx.origin used — phishing / auth bypass risk' },
  0x33: { severity: 'LOW', title: 'CALLER read (msg.sender)', description: 'msg.sender read — access control check' },
  0xf0: { severity: 'MEDIUM', title: 'CREATE (dynamic deployment)', description: 'Dynamic contract creation — may deploy untrusted code' },
  0xf5: { severity: 'HIGH', title: 'CREATE2 (deterministic deploy)', description: 'Deterministic contract creation — address depends on deployer + salt + initcode' },
  0xfa: { severity: 'LOW', title: 'STATICCALL', description: 'Static external call — no state modification allowed in callee' },
  0x42: { severity: 'MEDIUM', title: 'TIMESTAMP dependence', description: 'block.timestamp read — miner-influenced value' },
  0x43: { severity: 'LOW', title: 'NUMBER read (block.number)', description: 'block.number read — chain-level block height' },
  0xfe: { severity: 'LOW', title: 'INVALID opcode', description: 'Invalid opcode — typically assert/revert path' },
  0xfd: { severity: 'LOW', title: 'REVERT', description: 'REVERT — state changes reverted, gas not refunded' },
  0x31: { severity: 'LOW', title: 'BALANCE read', description: 'Account balance query' },
  0x1e: { severity: 'LOW', title: 'KECCAK256 hash', description: 'Keccak-256 — storage hashing / signature verification' },
};

const DANGEROUS_BY_NAME: Record<string, { byte: number; severity: BytecodeFinding['severity']; title: string; description: string }> = {};
for (const [hexByte, info] of Object.entries(DANGEROUS)) {
  const byte = Number(hexByte);
  const entry = OPCODE_TABLE[byte];
  if (entry) {
    DANGEROUS_BY_NAME[entry.name] = { byte, ...info };
    DANGEROUS_BY_NAME[entry.mnemonic] = { byte, ...info };
  }
}

function stripMetadata(hex: string): string {
  // CBOR-encoded Solidity metadata typically starts with a264697066735822 (ipfs) or a26669706673 (swarm)
  const ipfsPattern = 'a264697066735822';
  const swarmPattern = 'a266697066735820';

  let trimmed = hex;

  let idx = trimmed.indexOf(ipfsPattern);
  if (idx === -1) idx = trimmed.indexOf(swarmPattern);
  if (idx > 10) {
    trimmed = trimmed.substring(0, idx);
  }

  return trimmed;
}

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return bytes;
}

export function disassemble(bytecode: string): BytecodeOp[] {
  if (!bytecode || !bytecode.trim()) {
    throw new Error('No bytecode provided');
  }

  let hex = bytecode.trim();
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    hex = hex.substring(2);
  }

  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Malformed bytecode — invalid hex string');
  }

  hex = stripMetadata(hex);
  if (!hex) return [];

  const bytes = hexToBytes(hex);
  const ops: BytecodeOp[] = [];

  let i = 0;
  while (i < bytes.length) {
    const byte = bytes[i];
    const entry = OPCODE_TABLE[byte];

    if (!entry) {
      ops.push({
        pc: i,
        opcode: `0x${byte.toString(16).padStart(2, '0')}`,
        mnemonic: `UNKNOWN(0x${byte.toString(16).padStart(2, '0')})`,
        args: [],
        isPush: false,
        isDangerous: false,
      });
      i++;
      continue;
    }

    const pushArgs: number[] = [];
    let isPush = false;

    if (entry.pushBytes > 0) {
      isPush = true;
      for (let j = 0; j < entry.pushBytes && i + 1 + j < bytes.length; j++) {
        pushArgs.push(bytes[i + 1 + j]);
      }
    }

    const dangerInfo = DANGEROUS[byte];

    ops.push({
      pc: i,
      opcode: entry.name,
      mnemonic: entry.mnemonic,
      args: pushArgs,
      isPush,
      isDangerous: !!dangerInfo,
      danger: dangerInfo?.description,
    });

    i += 1 + entry.pushBytes;
  }

  return ops;
}

export function analyzeBytecode(bytecode: string): BytecodeAnalysis {
  if (!bytecode || !bytecode.trim()) {
    return {
      valid: false,
      bytecodeLength: 0,
      error: 'No bytecode provided',
      instructionCount: 0,
      pushconstantCount: 0,
      opcodes: [],
      findings: [],
      hasDelegatecall: false,
      hasSelfdestruct: false,
      hasSstore: false,
      hasCallValue: false,
      basicBlocks: [],
    };
  }

  let hex = bytecode.trim();
  if (hex.startsWith('0x') || hex.startsWith('0X')) {
    hex = hex.substring(2);
  }

  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    return {
      valid: false,
      bytecodeLength: 0,
      error: 'Malformed bytecode — invalid hex string',
      instructionCount: 0,
      pushconstantCount: 0,
      opcodes: [],
      findings: [],
      hasDelegatecall: false,
      hasSelfdestruct: false,
      hasSstore: false,
      hasCallValue: false,
      basicBlocks: [],
    };
  }

  const cleanedHex = stripMetadata(hex);
  const bytecodeLength = cleanedHex ? cleanedHex.length / 2 : 0;

  let ops: BytecodeOp[];
  try {
    ops = disassemble(bytecode);
  } catch (e) {
    return {
      valid: false,
      bytecodeLength: 0,
      error: e instanceof Error ? e.message : 'Disassembly failed',
      instructionCount: 0,
      pushconstantCount: 0,
      opcodes: [],
      findings: [],
      hasDelegatecall: false,
      hasSelfdestruct: false,
      hasSstore: false,
      hasCallValue: false,
      basicBlocks: [],
    };
  }

  const findings: BytecodeFinding[] = [];
  let hasDelegatecall = false;
  let hasSelfdestruct = false;
  let hasSstore = false;
  let hasCallValue = false;
  let pushconstantCount = 0;

  for (const op of ops) {
    if (op.isPush) pushconstantCount++;

    if (op.isDangerous) {
      const info = DANGEROUS_BY_NAME[op.opcode] ?? DANGEROUS_BY_NAME[op.mnemonic];
      if (info) {
        findings.push({
          opcode: op.opcode,
          pc: op.pc,
          severity: info.severity,
          title: info.title,
          description: info.description,
        });
      }
    }

    if (op.opcode === 'DELEGATECALL') hasDelegatecall = true;
    if (op.opcode === 'SELFDESTRUCT') hasSelfdestruct = true;
    if (op.opcode === 'SSTORE') hasSstore = true;
    if (op.opcode === 'CALLVALUE') hasCallValue = true;
  }

  // Basic-block reconstruction
  const basicBlocks = buildBasicBlocks(ops);

  return {
    valid: true,
    bytecodeLength,
    instructionCount: ops.length,
    pushconstantCount,
    opcodes: ops,
    findings,
    hasDelegatecall,
    hasSelfdestruct,
    hasSstore,
    hasCallValue,
    basicBlocks,
  };
}

function buildBasicBlocks(ops: BytecodeOp[]): BasicBlock[] {
  if (ops.length === 0) return [];

  // Identify block leaders: PC 0, every JUMPDEST, and targets of JUMP/JUMPI
  const jumpdests = new Set<number>();
  for (const op of ops) {
    if (op.opcode === 'JUMPDEST') jumpdests.add(op.pc);
  }

  // Scan for push-constant JUMP patterns to find implicit targets
  const pushValues = new Map<number, number>();
  for (let i = 0; i < ops.length; i++) {
    if (ops[i].isPush && ops[i].args.length > 0) {
      const val = ops[i].args.reduce((acc, b) => (acc << 8) | b, 0);
      pushValues.set(ops[i].pc, val);
    }
  }

  const leaders = new Set<number>();
  leaders.add(0);

  for (let i = 0; i < ops.length; i++) {
    if (ops[i].opcode === 'JUMP' || ops[i].opcode === 'JUMPI') {
      // Look back for the push that provided the target
      for (let j = i - 1; j >= Math.max(0, i - 4); j--) {
        if (ops[j].isPush && ops[j].args.length > 0) {
          const val = pushValues.get(ops[j].pc);
          if (val !== undefined && jumpdests.has(val)) {
            leaders.add(val);
          }
          break;
        }
      }
      // The instruction after JUMP/JUMPI is a leader
      if (ops[i].opcode === 'JUMP') {
        // Only unconditional JUMP — next instruction is unreachable directly
      } else {
        // JUMPI — fall-through is reachable
        if (i + 1 < ops.length) leaders.add(ops[i + 1].pc);
      }
    }
  }

  // Also add every JUMPDEST as a leader
  for (const jd of jumpdests) leaders.add(jd);

  const sortedLeaders = Array.from(leaders).sort((a, b) => a - b);

  // Build blocks: from one leader up to (but not including) the next leader or end
  const blocks: BasicBlock[] = [];
  for (let li = 0; li < sortedLeaders.length; li++) {
    const startPc = sortedLeaders[li];
    const endPc = li + 1 < sortedLeaders.length ? sortedLeaders[li + 1] : Infinity;

    const blockOps: string[] = [];
    let containsCall = false;
    let containsSstore = false;
    let containsDelegatecall = false;
    let containsSelfdestruct = false;

    for (const op of ops) {
      if (op.pc >= startPc && op.pc < endPc) {
        blockOps.push(op.mnemonic);
        if (op.opcode === 'CALL' || op.opcode === 'STATICCALL' || op.opcode === 'DELEGATECALL' || op.opcode === 'CALLCODE') {
          containsCall = true;
        }
        if (op.opcode === 'SSTORE') containsSstore = true;
        if (op.opcode === 'DELEGATECALL') containsDelegatecall = true;
        if (op.opcode === 'SELFDESTRUCT') containsSelfdestruct = true;
      }
    }

    const summary = buildBlockSummary(blockOps, containsCall, containsSstore, containsDelegatecall, containsSelfdestruct);

    blocks.push({
      start: startPc,
      end: endPc === Infinity ? (ops.length > 0 ? ops[ops.length - 1].pc + 1 : 0) : endPc,
      ops: blockOps,
      summary,
    });
  }

  return blocks;
}

function buildBlockSummary(
  ops: string[],
  hasCall: boolean,
  hasSstore: boolean,
  hasDelegatecall: boolean,
  hasSelfdestruct: boolean
): string {
  const parts: string[] = [];

  if (hasCall && hasSstore) {
    parts.push('CEI risk: external call before state write');
  } else if (hasCall) {
    parts.push('External call');
  } else if (hasSstore) {
    parts.push('State write (SSTORE)');
  }

  if (hasDelegatecall) {
    parts.push('Delegatecall — storage-context execution');
  }

  if (hasSelfdestruct) {
    parts.push('SELFDESTRUCT — contract destruction');
  }

  if (parts.length === 0) {
    parts.push(`Sequential flow: ${ops.length} ops`);
  }

  return parts.join('; ');
}
