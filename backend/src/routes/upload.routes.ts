import { Router, Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { runAudit, ProgressCallback } from '../engine/analyzer';
import { AuditReport } from '../types/index';
import { broadcast } from '../wsHub';
import { reportStore } from './audit.routes';

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 512 * 1024 }, // 512 KB
  fileFilter: (_req, file, cb) => {
    if (file.originalname.endsWith('.sol') || file.mimetype === 'application/octet-stream') {
      cb(null, true);
    } else {
      cb(new Error('Only .sol files are accepted'));
    }
  },
});

const router = Router();

/**
 * POST /api/upload
 * Accepts multipart form-data with a single .sol file.
 * Expects `contractName` in fields or filename is used.
 */
router.post(
  '/',
  upload.single('contract'),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.file) {
        res.status(400).json({ error: 'No .sol file uploaded' });
        return;
      }

      const sourceCode = req.file.buffer.toString('utf-8');
      const contractName =
        (req.body.contractName as string) ||
        req.file.originalname.replace(/\.sol$/, '');

      if (!sourceCode || !sourceCode.trim()) {
        res.status(400).json({ error: 'Uploaded file is empty' });
        return;
      }
      if (sourceCode.length > 1_500_000) {
        res.status(413).json({ error: 'Source code exceeds 1.5 MB limit' });
        return;
      }

      const onProgress: ProgressCallback = (stage, progress, message, data) => {
        broadcast({
          reportId: 'pending',
          stage,
          progress,
          message,
          data: data ?? undefined,
        });
      };

      const report = await runAudit({
        contractName: contractName.trim(),
        sourceCode,
        onProgress,
      });

      reportStore.set(report.reportId, report);
      res.status(200).json(report);
    } catch (err) {
      next(err);
    }
  }
);

// Multer / route errors.
router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof multer.MulterError) {
    res.status(400).json({ error: `Upload error: ${err.message}` });
  } else if (err instanceof Error) {
    res.status(400).json({ error: err.message });
  } else {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;