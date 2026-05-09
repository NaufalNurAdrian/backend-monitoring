import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const SessionLog = sequelize.define('SessionLog', {
  active_sessions: { type: DataTypes.INTEGER },
  max_sessions: { type: DataTypes.INTEGER },
  cpu_usage: { type: DataTypes.FLOAT },
  memory_usage: { type: DataTypes.FLOAT },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, {
  tableName: 'session_logs',
  timestamps: false,
});

export default SessionLog;