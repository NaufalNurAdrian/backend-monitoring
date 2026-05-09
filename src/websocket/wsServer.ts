import { Server } from 'http';
import { WebSocketServer, WebSocket } from 'ws';

import { setWsClients } from '../services/snmpPoller.js';

let clients: WebSocket[] = [];

export function initWebSocket(server: Server): void {
  const wss = new WebSocketServer({ server });

  wss.on('connection', (ws: WebSocket) => {
    console.log('[WS] Client connected');

    clients.push(ws);

    setWsClients(clients);

    ws.on('close', () => {
      clients = clients.filter((c) => c !== ws);

      setWsClients(clients);

      console.log('[WS] Client disconnected');
    });

    ws.on('error', (err: Error) => {
      console.error('[WS] Error:', err.message);
    });
  });

  console.log('[WS] WebSocket server ready');
}