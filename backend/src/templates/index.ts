import * as fs from 'fs';
import * as path from 'path';
import { TemplateInfo } from '../types/index';

const TEMPLATES_DIR = path.resolve(__dirname, '../../src/templates');

export function loadTemplates(): TemplateInfo[] {
  const files = fs
    .readdirSync(TEMPLATES_DIR)
    .filter((f) => f.endsWith('.sol'))
    .sort();

  return files.map((file) => {
    const sourceCode = fs.readFileSync(path.join(TEMPLATES_DIR, file), 'utf-8');
    const version =
      sourceCode.match(/pragma\s+solidity\s+([^;]+);/)?.[1]?.trim() ||
      '^0.8.20';
    const name = file.replace(/\.sol$/, '');
    const description = describe(name);
    return {
      id: name,
      name: toTitle(name),
      description: description.description,
      solidityVersion: version,
      sourceCode,
    };
  });
}

function toTitle(name: string): string {
  return name
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function describe(name: string): { description: string } {
  switch (name) {
    case 'secure-erc20':
      return {
        description:
          'Hardened ERC-20 with Ownable minting, EIP-2612 permit and safe token recovery.',
      };
    case 'secure-lending':
      return {
        description:
          'Overcollateralized lending pool with nonReentrant, CEI ordering and a Chainlink price oracle with staleness checks.',
      };
    case 'secure-amm':
      return {
        description:
          'Constant-product AMM with block-based TWAP, slippage + deadline guards and SafeERC20 transfers.',
      };
    default:
      return { description: 'Security-hardened Solidity template.' };
  }
}