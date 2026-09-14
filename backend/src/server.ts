import express, { Express, Request, Response, NextFunction } from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { WebSocketServer, WebSocket } from 'ws';
import { AddressInfo } from 'net';
import auditRoutes, { errorHandler as auditErrorHandler } from './routes/audit.routes';
import uploadRoutes from './routes/upload.routes';
import { registerClient, unregisterClient, heartbeatCheck, clientCount } from './wsHub';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
const WS_HEARTBEAT_MS = 30000;

export function createApplication(): { app: Express; server: http.Server; wss: WebSocketServer } {
  const app = express();

  // ---------- Security middleware ----------
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(
    cors({
      origin: process.env.CORS_ORIGIN
        ? process.env.CORS_ORIGIN.split(',')
        : ['http://localhost:5173', 'http://127.0.0.1:5173'],
      methods: ['GET', 'POST', 'OPTIONS'],
      credentials: true,
    })
  );

  app.use(express.json({ limit: '2mb' }));

  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      max: 30,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Too many requests, slow down.' },
    })
  );

  // ---------- Request logging (dev friendly) ----------
  app.use((req: Request, _res: Response, next: NextFunction) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
  });

  // ---------- Routes ----------
  app.get('/', (_req: Request, res: Response) => {
    res.json({
      service: 'smart-contract-auditor-backend',
      version: '1.0.0',
      endpoints: [
        'POST /api/audit',
        'POST /api/upload',
        'GET /api/report/:id',
        'GET /api/templates',
        'GET /api/demos',
        'GET /api/health',
        'WS /ws',
      ],
    });
  });

  app.use('/api', auditRoutes);
  app.use('/api/upload', uploadRoutes);

  // 404 handler.
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Global error handler.
  app.use(auditErrorHandler);

  // ---------- HTTP + WebSocket server ----------
  const server = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });

  server.on('upgrade', (request, socket, head) => {
    const { pathname } = new URL(request.url ?? '/', `http://${request.headers.host}`);

    if (pathname === '/ws') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    } else {
      socket.destroy();
    }
  });

  wss.on('connection', (ws: WebSocket) => {
    registerClient(ws);
    console.log(`[WS] client connected (${clientCount()} total)`);

    ws.send(
      JSON.stringify({
        type: 'connected',
        message: 'Connected to audit engine',
        timestamp: new Date().toISOString(),
      })
    );

    ws.on('message', (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        if (parsed && parsed.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
        }
      } catch {
        // ignore malformed frames
      }
    });

    ws.on('close', () => {
      unregisterClient(ws);
      console.log(`[WS] client disconnected (${clientCount()} total)`);
    });

    ws.on('error', () => {
      unregisterClient(ws);
    });
  });

  const heartbeatTimer = setInterval(() => {
    heartbeatCheck();
  }, WS_HEARTBEAT_MS);

  wss.on('close', () => {
    clearInterval(heartbeatTimer);
  });

  return { app, server, wss };
}

// Bootstrap when run directly (not imported by tests).
if (require.main === module) {
  const { app, server } = createApplication();

  server.listen(PORT, () => {
    const addr = server.address() as AddressInfo;
    console.log('==================================================');
    console.log('  Smart Contract Security Auditor — Backend');
    console.log(`  REST API : http://localhost:${addr.port}/api`);
    console.log(`  WebSocket: ws://localhost:${addr.port}/ws`);
    console.log('==================================================');
  });
}

export default createApplication;