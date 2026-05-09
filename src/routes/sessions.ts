import express, {
  Request,
  Response,
} from 'express';

import { Op } from 'sequelize';

import SessionLog from '../models/SessionLog.js';

const router = express.Router();

router.get(
  '/latest',
  async (_req: Request, res: Response) => {
    try {
      const data = await SessionLog.findOne({
        order: [['timestamp', 'DESC']],
      });

      res.json(data);
    } catch (err) {
      res.status(500).json({
        error: (err as Error).message,
      });
    }
  }
);

router.get(
  '/history',
  async (req: Request, res: Response) => {
    try {
      const hours =
        Number(req.query.hours) || 1;

      const since = new Date(
        Date.now() -
          hours * 60 * 60 * 1000
      );

      const data =
        await SessionLog.findAll({
          where: {
            timestamp: {
              [Op.gte]: since,
            },
          },
          order: [['timestamp', 'ASC']],
        });

      res.json(data);
    } catch (err) {
      res.status(500).json({
        error: (err as Error).message,
      });
    }
  }
);

export default router;