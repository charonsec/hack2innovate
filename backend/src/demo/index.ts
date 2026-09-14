import * as fs from 'fs';
import * as path from 'path';
import { DemoInfo } from '../types/index';

const DEMO_DIR = path.resolve(__dirname, '../../src/demo');

const META: Record<string, { category: 'vulnerable' | 'secure'; vulnerabilityClasses: string[] }> = {
  'reentrancy-demo': {
    category: 'vulnerable',
    vulnerabilityClasses: ['REENTRANCY'],
  },
  'oracle-demo': {
    category: 'vulnerable',
    vulnerabilityClasses: ['ORACLE_MANIPULATION'],
  },
  'flashloan-demo': {
    category: 'vulnerable',
    vulnerabilityClasses: ['FLASH_LOAN', 'ORACLE_MANIPULATION'],
  },
  'accesscontrol-demo': {
    category: 'vulnerable',
    vulnerabilityClasses: ['ACCESS_CONTROL'],
  },
  'amm-demo': {
    category: 'vulnerable',
    vulnerabilityClasses: ['ORACLE_MANIPULATION', 'FRONT_RUNNING'],
  },
  'secure-vault': {
    category: 'secure',
    vulnerabilityClasses: [],
  },
};

export function loadDemos(): DemoInfo[] {
  const files = fs
    .readdirSync(DEMO_DIR)
    .filter((f) => f.endsWith('.sol'))
    .sort();

  return files.map((file) => {
    const sourceCode = fs.readFileSync(path.join(DEMO_DIR, file), 'utf-8');
    const id = file.replace(/\.sol$/, '');
    const meta = META[id] ?? { category: 'vulnerable' as const, vulnerabilityClasses: [] as string[] };
    return {
      id,
      name: toTitle(id),
      category: meta.category,
      vulnerabilityClasses: meta.vulnerabilityClasses,
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
