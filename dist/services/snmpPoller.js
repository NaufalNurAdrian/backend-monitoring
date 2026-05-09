import * as snmp from 'net-snmp';
import dotenv from 'dotenv';
import BandwidthLog from '../models/BandwidthLog.js';
import SessionLog from '../models/SessionLog.js';
import InterfaceLog from '../models/InterfaceLog.js';
dotenv.config();
const OIDs = {
    // Interface (RFC1213-MIB) — pakai 32-bit counter
    ifDescr: '1.3.6.1.2.1.2.2.1.2',
    ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
    ifSpeed: '1.3.6.1.2.1.2.2.1.5',
    ifInOctets: '1.3.6.1.2.1.2.2.1.10', // ✅ bukan 31.1.1.1.6
    ifOutOctets: '1.3.6.1.2.1.2.2.1.16', // ✅ bukan 31.1.1.1.10
    // PAN-COMMON-MIB — OID yang benar
    panSessionUtil: '1.3.6.1.4.1.25461.2.1.2.3.1.0', // % session utilization
    panSessionMax: '1.3.6.1.4.1.25461.2.1.2.3.2.0', // max sessions
    panSessionActive: '1.3.6.1.4.1.25461.2.1.2.3.3.0', // total active sessions
    panSessionTCP: '1.3.6.1.4.1.25461.2.1.2.3.4.0', // active TCP sessions
    panSessionUDP: '1.3.6.1.4.1.25461.2.1.2.3.5.0', // active UDP sessions
    panSessionICMP: '1.3.6.1.4.1.25461.2.1.2.3.6.0', // active ICMP sessions
    // CPU — HOST-RESOURCES-MIB
    panCPUMgmt: '1.3.6.1.2.1.25.3.3.1.2.1', // management plane CPU
    panCPUData: '1.3.6.1.2.1.25.3.3.1.2.2', // dataplane CPU
    // Uptime
    sysUptime: '1.3.6.1.2.1.25.1.1.0',
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
function snmpGet(oid) {
    return new Promise((resolve, reject) => {
        session.get([oid], (err, varbinds) => {
            if (err)
                return reject(err);
            const vb = varbinds?.[0];
            if (!vb)
                return resolve(0);
            if (snmp.isVarbindError(vb))
                return resolve(0);
            const val = vb.value;
            if (Buffer.isBuffer(val))
                resolve(val.readUInt32BE(0) || 0);
            else
                resolve(Number(val) || 0);
        });
    });
}
function snmpWalk(oid) {
    return new Promise((resolve, reject) => {
        const results = [];
        session.walk(oid, 20, (varbinds) => {
            varbinds.forEach((vb) => {
                if (!snmp.isVarbindError(vb)) {
                    if (Buffer.isBuffer(vb.value)) {
                        // konversi buffer 4 byte ke number
                        vb.value = vb.value.length >= 4
                            ? vb.value.readUInt32BE(0)
                            : vb.value.readUIntBE(0, vb.value.length);
                    }
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
        const [sessionUtil, sessionMax, sessionActive, sessionTCP, sessionUDP, cpuMgmt, cpuData,] = await Promise.all([
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
        console.log(`[SNMP] Active: ${sessionActive} | Max: ${sessionMax} | CPU Mgmt: ${cpuMgmt}% | CPU Data: ${cpuData}%`);
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
        for (let i = 0; i < inOctets.length; i++) {
            const ifIndex = inOctets[i].oid.split('.').pop();
            const ifName = ifDescrs[i]?.value || `if${ifIndex}`;
            const currentIn = inOctets[i].value;
            const currentOut = outOctets[i]?.value || 0;
            const key = `if_${ifIndex}`;
            if (prevOctets[key]) {
                const deltaIn = currentIn - prevOctets[key].in;
                const deltaOut = currentOut - prevOctets[key].out;
                const mbpsIn = Math.max(0, (deltaIn * 8) / interval / 1_000_000);
                const mbpsOut = Math.max(0, (deltaOut * 8) / interval / 1_000_000);
                const bwData = {
                    interface_index: parseInt(ifIndex),
                    interface_name: ifName,
                    bytes_in: currentIn,
                    bytes_out: currentOut,
                    mbps_in: mbpsIn,
                    mbps_out: mbpsOut,
                };
                await BandwidthLog.create(bwData);
                broadcast({ type: 'bandwidth', data: bwData });
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
        for (let i = 0; i < ifDescrs.length; i++) {
            const ifIndex = ifDescrs[i].oid.split('.').pop();
            const ifData = {
                interface_index: parseInt(ifIndex),
                interface_name: ifDescrs[i].value,
                status: ifStatuses[i]?.value === 1 ? 'up' : 'down',
                speed: ifSpeeds[i]?.value || 0,
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
