import { WebSocketServer } from 'ws';
import { setWsClients } from '../services/snmpPoller.js';
let clients = [];
export function initWebSocket(server) {
    const wss = new WebSocketServer({ server });
    wss.on('connection', (ws) => {
        console.log('[WS] Client connected');
        clients.push(ws);
        setWsClients(clients);
        ws.on('close', () => {
            clients = clients.filter((c) => c !== ws);
            setWsClients(clients);
            console.log('[WS] Client disconnected');
        });
        ws.on('error', (err) => {
            console.error('[WS] Error:', err.message);
        });
    });
    console.log('[WS] WebSocket server ready');
}
