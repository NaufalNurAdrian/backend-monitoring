import express from 'express';
import { Op } from 'sequelize';
import BandwidthLog from '../models/BandwidthLog.js';
const router = express.Router();
router.get('/latest', async (req, res) => {
    try {
        const data = await BandwidthLog.findAll({
            order: [['timestamp', 'DESC']],
            limit: 20,
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
        const hours = Number(req.query.hours || 1);
        const since = new Date(Date.now() - hours * 60 * 60 * 1000);
        const data = await BandwidthLog.findAll({
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
