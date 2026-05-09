import express from 'express';
import { Op } from 'sequelize';
import SessionLog from '../models/SessionLog.js';
const router = express.Router();
router.get('/latest', async (_req, res) => {
    try {
        const data = await SessionLog.findOne({
            order: [['timestamp', 'DESC']],
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
        const hours = Number(req.query.hours) || 1;
        const since = new Date(Date.now() -
            hours * 60 * 60 * 1000);
        const data = await SessionLog.findAll({
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
