import express from 'express';
import { Op } from 'sequelize';
import ThreatLog from '../models/ThreatLog.js';
const router = express.Router();
router.get('/latest', async (_req, res) => {
    try {
        const data = await ThreatLog.findAll({
            order: [['timestamp', 'DESC']],
            limit: 10,
        });
        res.json(data);
    }
    catch (err) {
        res.status(500).json({
            error: err.message,
        });
    }
});
router.get('/history', async (req, res) => {
    try {
        const hours = Number(req.query.hours) || 24;
        const since = new Date(Date.now() -
            hours * 60 * 60 * 1000);
        const data = await ThreatLog.findAll({
            where: {
                timestamp: {
                    [Op.gte]: since,
                },
            },
            order: [['timestamp', 'ASC']],
        });
        res.json(data);
    }
    catch (err) {
        res.status(500).json({
            error: err.message,
        });
    }
});
export default router;
