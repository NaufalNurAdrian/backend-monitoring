import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const BandwidthLog = sequelize.define('BandwidthLog', {
  interface_name: { type: DataTypes.STRING },
  interface_index: { type: DataTypes.INTEGER },
  bytes_in: { type: DataTypes.BIGINT },
  bytes_out: { type: DataTypes.BIGINT },
  mbps_in: { type: DataTypes.FLOAT },
  mbps_out: { type: DataTypes.FLOAT },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, {
  tableName: 'bandwidth_logs',
  timestamps: false,
});

export default BandwidthLog;