// app/src/store/network.ts
// Network capture, WFP rules, DNS spoofing, interception, bandwidth, connections

import { create } from "zustand";
import { call } from "@/lib/rpc";

export type Packet = { id: number; ts: string; src: string; dst: string; protocol: string; length: number; info: string };
export type NetRule = { id: number; action: string; direction: string; protocol: string; port: number; pid: number };
export type Connection = { protocol: string; local: string; remote: string; state: string; pid: number; module: string };
export type BwStats = { rx_bytes: number; tx_bytes: number; rx_rate: number; tx_rate: number };
export type DnsEntry = { domain: string; ip: string; ttl: number };
export type InterceptEntry = { id: number; direction: string; protocol: string; payload_hex: string };
export type Stream = { id: string; src: string; dst: string; protocol: string; packets: number; bytes: number };

type NetworkStore = {
  capturing: boolean;
  packets: Packet[];
  rules: NetRule[];
  connections: Connection[];
  bw: BwStats | null;
  dns: DnsEntry[];
  intercepts: InterceptEntry[];
  streams: Stream[];
  busy: boolean;
  error: string | null;
  activeTab: string;

  setTab: (tab: string) => void;
  refreshStatus: () => Promise<void>;
  captureStart: (pid?: number) => Promise<void>;
  captureStop: () => Promise<void>;
  refreshPackets: (limit?: number, filter?: string) => Promise<void>;
  refreshDns: () => Promise<void>;
  refreshConnections: (pid?: number) => Promise<void>;
  refreshStreams: () => Promise<void>;
  refreshBw: () => Promise<void>;
  addRule: (action: string, direction: string, protocol: string, port?: number, pid?: number) => Promise<void>;
  removeRule: (pid?: number) => Promise<void>;
  clearRules: () => Promise<void>;
  exportPcap: (path: string) => Promise<void>;
  addDnsSpoof: (domain: string, ip: string, ttl?: number) => Promise<void>;
  removeDnsSpoof: (domain: string) => Promise<void>;
  interceptStart: (pid?: number, port?: number) => Promise<void>;
  interceptStop: () => Promise<void>;
  refreshIntercepts: () => Promise<void>;
  interceptRelease: (payload_hex: string) => Promise<void>;
  blockIp: (ip: string, direction?: string) => Promise<void>;
  blockPort: (port: number, direction?: string, protocol?: string) => Promise<void>;
  blockProcess: (pid: number, direction?: string) => Promise<void>;
  killConn: (protocol: string, srcPort: number, dstPort: number) => Promise<void>;
};

export const useNetwork = create<NetworkStore>((set) => ({
  capturing: false,
  packets: [],
  rules: [],
  connections: [],
  bw: null,
  dns: [],
  intercepts: [],
  streams: [],
  busy: false,
  error: null,
  activeTab: "capture",

  setTab: (tab) => set({ activeTab: tab }),

  refreshStatus: async () => {
    try {
      const r = await call<{ capturing: boolean }>("network", "status");
      set({ capturing: r.capturing, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  captureStart: async (pid?) => {
    try {
      await call("network", "capture_start", pid ? { pid } : {});
      set({ capturing: true, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  captureStop: async () => {
    try {
      await call("network", "capture_stop");
      set({ capturing: false, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  refreshPackets: async (limit = 200, filter?) => {
    set({ busy: true });
    try {
      const p: Record<string, unknown> = { limit };
      if (filter) p.filter = filter;
      const r = await call<{ packets: Packet[] }>("network", "packets", p);
      set({ packets: r.packets, busy: false, error: null });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  refreshDns: async () => {
    try {
      const r = await call<{ entries: DnsEntry[] }>("network", "dns");
      set({ dns: r.entries, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  refreshConnections: async (pid?) => {
    set({ busy: true });
    try {
      const r = await call<{ connections: Connection[] }>("network", "connections", pid ? { pid } : {});
      set({ connections: r.connections, busy: false, error: null });
    } catch (e: unknown) { set({ busy: false, error: (e as Error).message }); }
  },

  refreshStreams: async () => {
    try {
      const r = await call<{ streams: Stream[] }>("network", "streams");
      set({ streams: r.streams, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  refreshBw: async () => {
    try {
      const r = await call<BwStats>("network", "bw_stats");
      set({ bw: r, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  addRule: async (action, direction, protocol, port?, pid?) => {
    const p: Record<string, unknown> = { action_rule: action, direction, protocol };
    if (port) p.port = port;
    if (pid) p.pid = pid;
    await call("network", "rules_add", p);
  },

  removeRule: async (pid?) => {
    await call("network", "rules_remove", pid ? { pid } : {});
  },

  clearRules: async () => {
    await call("network", "rules_clear");
    set({ rules: [] });
  },

  exportPcap: async (path) => {
    await call("network", "export_pcap", { path });
  },

  addDnsSpoof: async (domain, ip, ttl = 60) => {
    await call("network", "dns_spoof_add", { domain, ip: ip, ttl });
  },

  removeDnsSpoof: async (domain) => {
    await call("network", "dns_spoof_remove", { domain });
  },

  interceptStart: async (pid?, port?) => {
    const p: Record<string, unknown> = {};
    if (pid) p.pid = pid;
    if (port) p.port = port;
    await call("network", "intercept_start", p);
  },

  interceptStop: async () => {
    await call("network", "intercept_stop");
  },

  refreshIntercepts: async () => {
    try {
      const r = await call<{ entries: InterceptEntry[] }>("network", "intercept_list");
      set({ intercepts: r.entries, error: null });
    } catch (e: unknown) { set({ error: (e as Error).message }); }
  },

  interceptRelease: async (payload_hex) => {
    await call("network", "intercept_release", { payload_hex });
  },

  blockIp: async (ip, direction = "both") => {
    await call("network", "block_ip", { ip, direction });
  },

  blockPort: async (port, direction = "both", protocol = "tcp") => {
    await call("network", "block_port", { port: port, direction, protocol });
  },

  blockProcess: async (pid, direction = "both") => {
    await call("network", "block_process", { pid, direction });
  },

  killConn: async (protocol, srcPort, dstPort) => {
    await call("network", "kill_conn", { protocol, src_port: srcPort, dst_port: dstPort });
  },
}));
