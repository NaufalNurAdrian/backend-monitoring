import express from 'express';
import cors from 'cors';
import http from 'http';
import dotenv from 'dotenv';
import sequelize from './config/database.js';
import { initWebSocket } from './websocket/wsServer.js';
import { startPoller } from './services/snmpPoller.js';
import bandwidthRoutes from './routes/bandwidth.js';
import threatRoutes from './routes/threats.js';
import sessionRoutes from './routes/sessions.js';
import interfaceRoutes from './routes/interfaces.js';
dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
app.use('/api/bandwidth', bandwidthRoutes);
app.use('/api/threats', threatRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/interfaces', interfaceRoutes);
app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        time: new Date(),
    });
});
const server = http.createServer(app);
initWebSocket(server);
const PORT = Number(process.env.PORT) || 5000;
sequelize.sync({ alter: true })
    .then(() => {
    console.log('[DB] Database synced');
    server.listen(PORT, () => {
        console.log(`[SERVER] Running on port ${PORT}`);
        startPoller();
    });
})
    .catch((err) => {
    console.error('[DB] Error:', err);
});
