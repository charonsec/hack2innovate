import { WebSocket } from 'ws';

export type WsClient = WebSocket & { isAlive: boolean };

const clients = new Set<WsClient>();

export function registerClient(ws: WebSocket): void {
  const client = ws as WsClient;
  client.isAlive = true;
  client.on('pong', () => {
    client.isAlive = true;
  });
  clients.add(client);
}

export function unregisterClient(ws: WebSocket): void {
  clients.delete(ws as WsClient);
}

export function broadcast(message: unknown): void {
  const data = JSON.stringify(message);
  for (const client of clients) {
    if (client.readyState === client.OPEN) {
      client.send(data);
    }
  }
}

export function sendTo(ws: WebSocket, message: unknown): void {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

export function heartbeatCheck(): number {
  for (const client of clients) {
    if (client.isAlive === false) {
      client.terminate();
      clients.delete(client);
      continue;
    }
    client.isAlive = false;
    client.ping();
  }
  return clients.size;
}

export function clientCount(): number {
  return clients.size;
}