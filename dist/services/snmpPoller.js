import * as snmp from "net-snmp";
import dotenv from "dotenv";
import BandwidthLog from "../models/BandwidthLog.js";
import ThreatLog from "../models/ThreatLog.js";
import SessionLog from "../models/SessionLog.js";
import InterfaceLog from "../models/InterfaceLog.js";
dotenv.config();
const OIDs = {
    ifDescr: "1.3.6.1.2.1.2.2.1.2",
    ifOperStatus: "1.3.6.1.2.1.2.2.1.8",
    ifSpeed: "1.3.6.1.2.1.2.2.1.5",
    ifInOctets: "1.3.6.1.2.1.2.2.1.10",
    ifOutOctets: "1.3.6.1.2.1.2.2.1.16",
    panSessionUtil: "1.3.6.1.4.1.25461.2.1.2.3.1.0",
    panSessionMax: "1.3.6.1.4.1.25461.2.1.2.3.2.0",
    panSessionActive: "1.3.6.1.4.1.25461.2.1.2.3.3.0",
    panSessionTCP: "1.3.6.1.4.1.25461.2.1.2.3.4.0",
    panSessionUDP: "1.3.6.1.4.1.25461.2.1.2.3.5.0",
    panCPUMgmt: "1.3.6.1.2.1.25.3.3.1.2.1",
    panCPUData: "1.3.6.1.2.1.25.3.3.1.2.2",
};
const session = snmp.createSession(process.env.PALO_ALTO_IP, process.env.SNMP_COMMUNITY, { version: snmp.Version2c });
let prevOctets = {};
let wsClients = [];
export function setWsClients(clients) {
    wsClients = clients;
}
function broadcast(data) {
    wsClients.forEach((client) => {
        if (client.readyState === 1) {
            client.send(JSON.stringify(data));
        }
    });
}
function toNumber(val) {
    if (val === null || val === undefined)
        return 0;
    if (Buffer.isBuffer(val)) {
        if (val.length === 0)
            return 0;
        if (val.length >= 4)
            return val.readUInt32BE(0);
        return val.readUIntBE(0, val.length);
    }
    return Number(val) || 0;
}
function toStr(val) {
    if (Buffer.isBuffer(val)) {
        return val.toString('utf8').replace(/\0/g, '').trim();
    }
    return String(val ?? '');
}
function getIndex(oid) {
    return parseInt(oid.split('.').pop() ?? '0');
}
function snmpGet(oid) {
    return new Promise((resolve, reject) => {
        session.get([oid], (err, varbinds) => {
            if (err)
                return reject(err);
            const vb = varbinds?.[0];
            if (!vb || snmp.isVarbindError(vb))
                return resolve(0);
            resolve(toNumber(vb.value));
        });
    });
}
function snmpWalk(oid) {
    return new Promise((resolve, reject) => {
        const results = [];
        session.walk(oid, 20, (varbinds) => {
            varbinds.forEach((vb) => {
                if (!snmp.isVarbindError(vb)) {
                    results.push(vb);
                }
            });
        }, (err) => {
            if (err)
                reject(err);
            else
                resolve(results);
        });
    });
}
async function pollSystem() {
    try {
        const [sessionUtil, sessionMax, sessionActive, sessionTCP, sessionUDP, cpuMgmt, cpuData] = await Promise.all([
            snmpGet(OIDs.panSessionUtil),
            snmpGet(OIDs.panSessionMax),
            snmpGet(OIDs.panSessionActive),
            snmpGet(OIDs.panSessionTCP),
            snmpGet(OIDs.panSessionUDP),
            snmpGet(OIDs.panCPUMgmt),
            snmpGet(OIDs.panCPUData),
        ]);
        const sessionData = {
            active_sessions: sessionActive,
            max_sessions: sessionMax,
            cpu_usage: cpuMgmt,
            memory_usage: cpuData,
        };
        await SessionLog.create(sessionData);
        broadcast({ type: 'session', data: sessionData });
        await ThreatLog.create({ threat_count: 0, threat_type: 'total', severity: 'mixed' });
        console.log(`[SNMP] Active: ${sessionActive} | Max: ${sessionMax} | CPU: ${cpuMgmt}%`);
    }
    catch (err) {
        console.error('[SNMP] System poll error:', err.message);
    }
}
async function pollBandwidth() {
    try {
        const [inOctets, outOctets, ifDescrs] = await Promise.all([
            snmpWalk(OIDs.ifInOctets),
            snmpWalk(OIDs.ifOutOctets),
            snmpWalk(OIDs.ifDescr),
        ]);
        const interval = parseInt(process.env.POLL_INTERVAL) / 1000;
        // Build maps by ifIndex
        const descrMap = {};
        for (const vb of ifDescrs) {
            descrMap[getIndex(vb.oid)] = toStr(vb.value);
        }
        const outMap = {};
        for (const vb of outOctets) {
            outMap[getIndex(vb.oid)] = toNumber(vb.value);
        }
        for (const vb of inOctets) {
            const ifIndex = getIndex(vb.oid);
            // Hanya proses interface fisik (index 1-50)
            if (ifIndex > 50)
                continue;
            const ifName = descrMap[ifIndex] || `if${ifIndex}`;
            const currentIn = toNumber(vb.value);
            const currentOut = outMap[ifIndex] || 0;
            const key = `if_${ifIndex}`;
            if (prevOctets[key]) {
                const deltaIn = currentIn - prevOctets[key].in;
                const deltaOut = currentOut - prevOctets[key].out;
                const mbpsIn = Math.max(0, (deltaIn * 8) / interval / 1_000_000);
                const mbpsOut = Math.max(0, (deltaOut * 8) / interval / 1_000_000);
                const bwData = {
                    interface_index: ifIndex,
                    interface_name: ifName,
                    bytes_in: currentIn,
                    bytes_out: currentOut,
                    mbps_in: mbpsIn,
                    mbps_out: mbpsOut,
                };
                await BandwidthLog.create(bwData);
                broadcast({ type: 'bandwidth', data: bwData });
                console.log(`[BW] ${ifName}: in=${mbpsIn.toFixed(2)}Mbps out=${mbpsOut.toFixed(2)}Mbps`);
            }
            prevOctets[key] = { in: currentIn, out: currentOut };
        }
    }
    catch (err) {
        console.error('[SNMP] Bandwidth poll error:', err.message);
    }
}
async function pollInterfaces() {
    try {
        const [ifDescrs, ifStatuses, ifSpeeds] = await Promise.all([
            snmpWalk(OIDs.ifDescr),
            snmpWalk(OIDs.ifOperStatus),
            snmpWalk(OIDs.ifSpeed),
        ]);
        const statusMap = {};
        for (const vb of ifStatuses) {
            statusMap[getIndex(vb.oid)] = toNumber(vb.value);
        }
        const speedMap = {};
        for (const vb of ifSpeeds) {
            speedMap[getIndex(vb.oid)] = toNumber(vb.value);
        }
        for (const vb of ifDescrs) {
            const ifIndex = getIndex(vb.oid);
            // Hanya proses interface fisik (index 1-50)
            if (ifIndex > 50)
                continue;
            const ifData = {
                interface_index: ifIndex,
                interface_name: toStr(vb.value),
                status: statusMap[ifIndex] === 1 ? 'up' : 'down',
                speed: speedMap[ifIndex] || 0,
            };
            await InterfaceLog.create(ifData);
            broadcast({ type: 'interface', data: ifData });
        }
    }
    catch (err) {
        console.error('[SNMP] Interface poll error:', err.message);
    }
}
async function pollAll() {
    await Promise.all([pollSystem(), pollBandwidth(), pollInterfaces()]);
}
export function startPoller() {
    console.log(`[SNMP] Poller started — interval: ${process.env.POLL_INTERVAL}ms`);
    pollAll();
    setInterval(pollAll, parseInt(process.env.POLL_INTERVAL));
}
