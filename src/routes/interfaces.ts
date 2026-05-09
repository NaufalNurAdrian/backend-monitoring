import express, {
  Request,
  Response,
} from 'express';

import InterfaceLog from '../models/InterfaceLog.js';

const router = express.Router();

router.get(
  '/latest',
  async (_req: Request, res: Response) => {
    try {
      const data =
        await InterfaceLog.findAll({
          order: [['timestamp', 'DESC']],
          limit: 20,
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