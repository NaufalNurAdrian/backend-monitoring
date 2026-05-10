import * as snmp from "net-snmp";
import dotenv from "dotenv";
import { WebSocket } from "ws";

import BandwidthLog from "../models/BandwidthLog.js";
import ThreatLog from "../models/ThreatLog.js";
import SessionLog from "../models/SessionLog.js";
import InterfaceLog from "../models/InterfaceLog.js";

dotenv.config();

const OIDs = {
  ifDescr:          "1.3.6.1.2.1.2.2.1.2",
  ifOperStatus:     "1.3.6.1.2.1.2.2.1.8",
  ifSpeed:          "1.3.6.1.2.1.2.2.1.5",
  ifInOctets:       "1.3.6.1.2.1.2.2.1.10",
  ifOutOctets:      "1.3.6.1.2.1.2.2.1.16",
  panSessionUtil:   "1.3.6.1.4.1.25461.2.1.2.3.1.0",
  panSessionMax:    "1.3.6.1.4.1.25461.2.1.2.3.2.0",
  panSessionActive: "1.3.6.1.4.1.25461.2.1.2.3.3.0",
  panSessionTCP:    "1.3.6.1.4.1.25461.2.1.2.3.4.0",
  panSessionUDP:    "1.3.6.1.4.1.25461.2.1.2.3.5.0",
  panCPUMgmt:       "1.3.6.1.2.1.25.3.3.1.2.1",
  panCPUData:       "1.3.6.1.2.1.25.3.3.1.2.2",
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

function toNumber(val: any): number {
  if (val === null || val === undefined) return 0;
  if (Buffer.isBuffer(val)) {
    if (val.length === 0) return 0;
    if (val.length >= 4) return val.readUInt32BE(0);
    return val.readUIntBE(0, val.length);
  }
  return Number(val) || 0;
}

function toStr(val: any): string {
  if (Buffer.isBuffer(val)) {
    return val.toString('utf8').replace(/\0/g, '').trim();
  }
  return String(val ?? '');
}

function getIndex(oid: string): number {
  return parseInt(oid.split('.').pop() ?? '0');
}

function isValidIfName(name: string): boolean {
  return /^[\x20-\x7E]+$/.test(name) && name.length > 0 && name.length < 50;
}

function snmpGet(oid: string): Promise<number> {
  return new Promise((resolve, reject) => {
    (session.get as any)([oid], (err: any, varbinds: any[]) => {
      if (err) return reject(err);
      const vb = varbinds?.[0];
      if (!vb || snmp.isVarbindError(vb)) return resolve(0);
      resolve(toNumber(vb.value));
    });
  });
}

function snmpWalk(oid: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const results: any[] = [];
    (session.walk as any)(
      oid,
      20,
      (varbinds: any[]) => {
        varbinds.forEach((vb: any) => {
          if (!snmp.isVarbindError(vb)) {
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
    const [sessionUtil, sessionMax, sessionActive, sessionTCP, sessionUDP, cpuMgmt, cpuData] =
      await Promise.all([
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

    const descrMap: Record<number, string> = {};
    for (const vb of ifDescrs) {
      const name = toStr(vb.value);
      if (isValidIfName(name)) {
        descrMap[getIndex(vb.oid)] = name;
      }
    }

    const outMap: Record<number, number> = {};
    for (const vb of outOctets) {
      outMap[getIndex(vb.oid)] = toNumber(vb.value);
    }

    for (const vb of inOctets) {
      const ifIndex = getIndex(vb.oid);
      if (ifIndex > 50) continue;

      const ifName = descrMap[ifIndex];
      if (!ifName || !isValidIfName(ifName)) continue;

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

    const statusMap: Record<number, number> = {};
    for (const vb of ifStatuses) {
      statusMap[getIndex(vb.oid)] = toNumber(vb.value);
    }

    const speedMap: Record<number, number> = {};
    for (const vb of ifSpeeds) {
      speedMap[getIndex(vb.oid)] = toNumber(vb.value);
    }

    for (const vb of ifDescrs) {
      const ifIndex = getIndex(vb.oid);
      if (ifIndex > 50) continue;

      const ifName = toStr(vb.value);
      if (!isValidIfName(ifName)) continue;

      const ifData = {
        interface_index: ifIndex,
        interface_name: ifName,
        status: statusMap[ifIndex] === 1 ? 'up' : 'down',
        speed: speedMap[ifIndex] || 0,
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