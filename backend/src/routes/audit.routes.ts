import { Router, Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { runAudit, ProgressCallback } from '../engine/analyzer';
import { analyzeBytecode } from '../engine/bytecode';
import { AuditReport } from '../types/index';
import { sendTo, broadcast } from '../wsHub';
import { WebSocket } from 'ws';
import { loadTemplates } from '../templates/index';
import { loadDemos } from '../demo/index';

// In-memory report store keyed by reportId.
export const reportStore = new Map<string, AuditReport>();

const router = Router();

/**
 * POST /api/audit
 * Accepts JSON body: { contractName, sourceCode, contractAddress?, network? }
 * Also supports WS-driven progress streaming.
 */
router.post('/audit', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { contractName, sourceCode, contractAddress, network, bytecode } = req.body;

    if (!contractName || typeof contractName !== 'string' || !contractName.trim()) {
      res.status(400).json({ error: 'contractName is required' });
      return;
    }
    if (!sourceCode || typeof sourceCode !== 'string' || !sourceCode.trim()) {
      res.status(400).json({ error: 'sourceCode is required' });
      return;
    }
    if (sourceCode.length > 1_500_000) {
      res.status(413).json({ error: 'sourceCode exceeds 1.5 MB limit' });
      return;
    }

    const reportId = uuidv4();
    const progressWs = req.headers['x-scan-ws-id'] as string | undefined;

    const onProgress: ProgressCallback = (
      stage,
      progress,
      message,
      data
    ) => {
      const payload = {
        reportId,
        stage,
        progress,
        message,
        data: data ?? undefined,
      };
      broadcast(payload);
    };

    // Run the async audit pipeline.
    const report = await runAudit({
      contractName: contractName.trim(),
      sourceCode,
      contractAddress: contractAddress ?? undefined,
      network: network ?? undefined,
      bytecode: bytecode ?? undefined,
      onProgress,
    });

    reportStore.set(report.reportId, report);

    res.status(200).json(report);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/bytecode
 * Standalone EVM bytecode disassembly + opcode analysis.
 * Accepts JSON body: { bytecode }
 */
router.post('/bytecode', (req: Request, res: Response) => {
  try {
    const { bytecode } = req.body;

    if (!bytecode || typeof bytecode !== 'string' || !bytecode.trim()) {
      res.status(200).json({ analysis: analyzeBytecode('') });
      return;
    }
    if (bytecode.length > 10_000_000) {
      res.status(413).json({ error: 'bytecode exceeds 10 MB limit' });
      return;
    }

    const analysis = analyzeBytecode(bytecode);

    // Invalid hex is a valid analysis outcome, not a protocol error.
    res.status(200).json({ analysis });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : 'Internal server error' });
  }
});

/**
 * GET /api/report/:id
 * Retrieve a previously completed audit report.
 */
router.get('/report/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const report = reportStore.get(id);
  if (!report) {
    res.status(404).json({ error: 'Report not found' });
    return;
  }
  res.status(200).json(report);
});

/**
 * GET /api/templates
 * Return all built-in secure Solidity templates.
 */
router.get('/templates', (_req: Request, res: Response) => {
  try {
    const templates = loadTemplates();
    res.status(200).json(templates);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load templates' });
  }
});

/**
 * GET /api/demos
 * Return all built-in demo contracts (vulnerable + secure).
 */
router.get('/demos', (_req: Request, res: Response) => {
  try {
    const demos = loadDemos();
    res.status(200).json(demos);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load demos' });
  }
});

/**
 * GET /api/health
 */
router.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    memory: process.memoryUsage(),
    reportCount: reportStore.size,
  });
});

// Global error handler mounted after routes.
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  const message = err instanceof Error ? err.message : 'Internal server error';
  console.error('[AuditRoute Error]', message);
  res.status(500).json({ error: message });
}

export default router;