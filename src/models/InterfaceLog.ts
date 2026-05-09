import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const InterfaceLog = sequelize.define('InterfaceLog', {
  interface_index: { type: DataTypes.INTEGER },
  interface_name: { type: DataTypes.STRING },
  status: { type: DataTypes.STRING },
  speed: { type: DataTypes.BIGINT },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, {
  tableName: 'interface_logs',
  timestamps: false,
});

export default InterfaceLog;