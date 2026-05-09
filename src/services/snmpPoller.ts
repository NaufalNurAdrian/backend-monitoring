import * as snmp from 'net-snmp';
import dotenv from 'dotenv';
import { WebSocket } from 'ws';

import BandwidthLog from '../models/BandwidthLog.js';
import ThreatLog from '../models/ThreatLog.js';
import SessionLog from '../models/SessionLog.js';
import InterfaceLog from '../models/InterfaceLog.js';

dotenv.config();

const OIDs = {
  ifDescr:        '1.3.6.1.2.1.2.2.1.2',
  ifOperStatus:   '1.3.6.1.2.1.2.2.1.8',
  ifSpeed:        '1.3.6.1.2.1.2.2.1.5',
  ifInOctets:     '1.3.6.1.2.1.31.1.1.1.6',
  ifOutOctets:    '1.3.6.1.2.1.31.1.1.1.10',
  panSessions:    '1.3.6.1.4.1.25461.2.1.2.3.2.0',
  panMaxSessions: '1.3.6.1.4.1.25461.2.1.2.3.3.0',
  panCPU:         '1.3.6.1.4.1.25461.2.1.2.3.1.0',
  panMemory:      '1.3.6.1.4.1.25461.2.1.2.3.4.0',
  panThreat:      '1.3.6.1.4.1.25461.2.1.2.1.19.0',
};

const session = snmp.createSession(
  process.env.PALO_ALTO_IP as string,
  process.env.SNMP_COMMUNITY as string,
  { version: snmp.Version2c }
);

let prevOctets: Record<string, { in: number; out: number }> = {};
let wsClients: WebSocket[] = [];

export function setWsClients(clients: WebSocket[]): void {
  wsClients = clients;
}

function broadcast(data: unknown): void {
  wsClients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(JSON.stringify(data));
    }
  });
}

function snmpGet(oid: string): Promise<number> {
  return new Promise((resolve, reject) => {
    (session.get as any)([oid], (err: any, varbinds: any[]) => {
      if (err) return reject(err);
      const vb = varbinds?.[0];
      if (!vb) return resolve(0);
      if (snmp.isVarbindError(vb)) return resolve(0);
      const val = vb.value;
      if (Buffer.isBuffer(val)) resolve(val.readUInt32BE(0) || 0);
      else resolve(Number(val) || 0);
    });
  });
}

function snmpWalk(oid: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const results: any[] = [];
    session.walk(
      oid,
      20,
      (varbinds: any[]) => {
        varbinds.forEach((vb: any) => {
          if (!snmp.isVarbindError(vb)) {
            // konversi buffer ke string atau number
            if (Buffer.isBuffer(vb.value)) {
              vb.value = vb.value.toString('utf8').replace(/\0/g, '').trim() || 0;
            }
            results.push(vb);
          }
        });
      },
      (err: any) => {
        if (err) reject(err);
        else resolve(results);
      }
    );
  });
}

async function pollSystem(): Promise<void> {
  try {
    const [activeSessions, maxSessions, cpuUsage, memUsage] = await Promise.all([
      snmpGet(OIDs.panSessions),
      snmpGet(OIDs.panMaxSessions),
      snmpGet(OIDs.panCPU),
      snmpGet(OIDs.panMemory),
    ]);

    // threat optional
    let threatCount = 0;
    try { threatCount = await snmpGet(OIDs.panThreat); } catch { threatCount = 0; }

    const sessionData = {
      active_sessions: activeSessions,
      max_sessions: maxSessions,
      cpu_usage: cpuUsage,
      memory_usage: memUsage,
    };
    await SessionLog.create(sessionData);
    broadcast({ type: 'session', data: sessionData });

    const threatData = {
      threat_count: threatCount,
      threat_type: 'total',
      severity: 'mixed',
    };
    await ThreatLog.create(threatData);
    broadcast({ type: 'threat', data: threatData });

    console.log(`[SNMP] Sessions: ${activeSessions} | CPU: ${cpuUsage}% | Threats: ${threatCount}`);
  } catch (err) {
    console.error('[SNMP] System poll error:', (err as Error).message);
  }
}

async function pollBandwidth(): Promise<void> {
  try {
    const [inOctets, outOctets, ifDescrs] = await Promise.all([
      snmpWalk(OIDs.ifInOctets),
      snmpWalk(OIDs.ifOutOctets),
      snmpWalk(OIDs.ifDescr),
    ]);

    const interval = parseInt(process.env.POLL_INTERVAL as string) / 1000;

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
  } catch (err) {
    console.error('[SNMP] Bandwidth poll error:', (err as Error).message);
  }
}

async function pollInterfaces(): Promise<void> {
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
  } catch (err) {
    console.error('[SNMP] Interface poll error:', (err as Error).message);
  }
}

async function pollAll(): Promise<void> {
  await Promise.all([pollSystem(), pollBandwidth(), pollInterfaces()]);
}

export function startPoller(): void {
  console.log(`[SNMP] Poller started — interval: ${process.env.POLL_INTERVAL}ms`);
  pollAll();
  setInterval(pollAll, parseInt(process.env.POLL_INTERVAL as string));
}

