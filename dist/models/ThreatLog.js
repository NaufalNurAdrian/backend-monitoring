import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';
const ThreatLog = sequelize.define('ThreatLog', {
    threat_count: { type: DataTypes.INTEGER },
    threat_type: { type: DataTypes.STRING },
    severity: { type: DataTypes.STRING },
    timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
}, {
    tableName: 'threat_logs',
    timestamps: false,
});
export default ThreatLog;
