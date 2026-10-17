import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { Monitoring, RETENTION_MS, firewallKey, normalizeInterfaces, normalizeOnline, normalizePorts, normalizeSystem, normalizeVpn } from "./monitoring.js";

const firewall = { id: "fw/1", siteId: "site/1", organizationId: "org" };

async function withMonitor(run) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "nebula-monitor-"));
  let time = 1_800_000_000_000;
  const requests = [];
  let fail = false;
  const options = {
    dataDir, env: { NEBULA_API_KEY: "secret-key" }, now: () => time,
    fetchImpl: async (url) => {
      requests.push(url);
      if (fail) return { ok: false, status: 429 };
      let body;
      if (url.endsWith("vpn-status")) body = { sites: [{ siteId: "remote", tunnel: [{ status: "up" }] }] };
      else if (url.endsWith("online-status")) body = [
        { devId: "fw/1", currentStatus: "ONLINE" },
        { devId: "fw2", currentStatus: "ONLINE" },
      ];
      else if (url.endsWith("ports-status")) body = [{ portNumber: "1", portGroup: "wan-1", linkSpeed: "1000 Mbps" }];
      else if (url.endsWith("interface-settings")) body = {
        wan: [{ interface: "WAN1", enabled: true, portGroupId: "wan-1", ipv4Address: "192.0.2.1", ipv4Gateway: "192.0.2.254" }],
        lan: [],
      };
      else body = { cpuUsage: 20, memUsage: 40, sessions: 0 };
      return { ok: true, json: async () => body };
    },
  };
  const monitor = new Monitoring(options);
  try { await run(monitor, { options, requests, advance: milliseconds => { time += milliseconds; }, fail: () => { fail = true; } }); }
  finally { monitor.close(); await rm(dataDir, { recursive: true, force: true }); }
}

test("normalizes null metrics and unknown VPN states without assuming healthy", () => {
  assert.deepEqual(normalizeSystem({ cpuUsage: null, memUsage: 101, sessions: 0 }), { cpu: null, ram: null, sessions: 0 });
  assert.equal(normalizeVpn({ sites: [{ siteId: "peer", tunnel: [null] }] }).tunnels[0].state, "unknown");
  assert.equal(normalizeVpn({ gateways: [] }).tunnels.length, 0);
  assert.throws(() => normalizeVpn({}), /INVALID_RESPONSE/);
});

test("normalizes cloud state and keeps WAN data limited to status fields", () => {
  assert.deepEqual(normalizeOnline([
    { devId: "fw1", currentStatus: "ONLINE" },
    { devId: "fw2", currentStatus: "OFFLINE" },
    { devId: "fw3", currentStatus: null },
  ]), [
    { id: "fw1", status: "online" },
    { id: "fw2", status: "offline" },
    { id: "fw3", status: "unknown" },
  ]);
  assert.deepEqual(normalizePorts([
    { portNumber: "1", portGroup: "wan-1", linkSpeed: "1000 Mbps" },
    { portNumber: "2", portGroup: null, linkSpeed: null },
    { portNumber: "3", portGroup: "wan-2", linkSpeed: "No Link" },
  ]).ports.map(port => port.linkState), ["up", "unknown", "down"]);
  assert.deepEqual(normalizeInterfaces({
    wan: [{ interface: "WAN1", portGroupId: "wan-1", enabled: true, ipv4Address: "192.0.2.1", ipv4Gateway: "192.0.2.254" }],
    lan: [],
  }), {
    wan: [{ name: "WAN1", portGroupId: "wan-1", enabled: true, hasAddress: true, hasGateway: true }],
    lan: [],
  });
  assert.throws(() => normalizeOnline({}), /INVALID_RESPONSE/);
});

test("collects once per site, independently schedules system and VPN, and persists", async () => {
  await withMonitor(async (monitor, { requests, advance, options }) => {
    const devices = [firewall, { ...firewall, id: "fw2" }];
    await Promise.all([monitor.tick(devices), monitor.tick(devices)]);
    assert.equal(requests.length, 8);
    assert.ok(requests.some(url => url.includes("site%2F1/gw/fw%2F1")));
    assert.equal(requests.filter(url => url.endsWith("online-status")).length, 1);
    assert.equal(monitor.snapshot(devices).devices[0].online.data.status, "online");
    assert.deepEqual(monitor.snapshot(devices).devices[0].interfaces.data.wan[0], {
      name: "WAN1", portGroupId: "wan-1", enabled: true, hasAddress: true, hasGateway: true,
    });
    advance(60_000);
    await monitor.tick(devices);
    assert.equal(requests.length, 10);
    const reopened = new Monitoring(options);
    try {
      assert.equal(reopened.snapshot(devices).devices[0].system.data.sessions, 0);
      assert.equal(reopened.history(firewallKey(firewall)).length, 1);
      assert.equal(reopened.history(firewallKey(firewall), "ports").length, 1);
    } finally { reopened.close(); }
    advance(240_000);
    await monitor.tick(devices);
    assert.equal(requests.length, 18);
  });
});

test("requires consecutive saturation, resolves alerts and expires history after 48h", async () => {
  await withMonitor(async (monitor, { advance }) => {
    const key = firewallKey(firewall);
    const high = { ok: true, data: { cpu: 95, ram: 10, sessions: 3 } };
    monitor.record(key, "system", high);
    assert.equal(monitor.snapshot([firewall]).alerts.some(alert => alert.message.includes("CPU")), false);
    advance(300_000);
    monitor.record(key, "system", high);
    assert.equal(monitor.snapshot([firewall]).alerts.find(alert => alert.message.includes("CPU")).resolved, null);
    advance(300_000);
    monitor.record(key, "system", { ok: true, data: { cpu: 10, ram: 10, sessions: 0 } });
    assert.ok(monitor.snapshot([firewall]).alerts.find(alert => alert.message.includes("CPU")).resolved);
    advance(RETENTION_MS + 1);
    assert.equal(monitor.history(key).length, 0);
    assert.equal(monitor.snapshot([firewall]).devices[0].system.state, "pending");
  });
});

test("handles rate limiting, marks failures and stale samples, and never leaks credentials", async () => {
  await withMonitor(async (monitor, { advance, fail, requests }) => {
    await monitor.tick([firewall]);
    advance(60_000);
    fail();
    await monitor.tick([firewall]);
    assert.equal(monitor.snapshot([firewall]).devices[0].vpn.state, "error");
    const count = requests.length;
    advance(60_000);
    await monitor.tick([firewall]);
    assert.equal(requests.length, count);
    advance(800_000);
    const snapshot = monitor.snapshot([firewall]);
    assert.equal(snapshot.devices[0].system.state, "stale");
    assert.equal(JSON.stringify(snapshot).includes("secret-key"), false);
  });
});

test("confirms cloud outages and mapped WAN link loss on consecutive samples", async () => {
  await withMonitor(async (monitor, { advance }) => {
    const key = firewallKey(firewall);
    const online = status => ({ ok: true, data: { status } });
    const ports = state => ({ ok: true, data: { ports: [{ portNumber: "1", portGroup: "wan-1", linkSpeed: state === "down" ? "No Link" : "1000 Mbps", linkState: state }] } });
    monitor.record(key, "interfaces", { ok: true, data: { wan: [{ enabled: true, portGroupId: "wan-1" }], lan: [] } });
    monitor.record(key, "online", online("offline"));
    monitor.record(key, "ports", ports("down"));
    advance(60_000);
    monitor.record(key, "online", online("offline"));
    monitor.record(key, "ports", ports("down"));
    let active = monitor.snapshot([firewall]).alerts.filter(alert => !alert.resolved);
    assert.ok(active.some(alert => alert.kind === "online" && alert.message.includes("hors ligne")));
    assert.ok(active.some(alert => alert.kind === "ports" && alert.message.includes("ports WAN")));
    advance(60_000);
    monitor.record(key, "online", online("online"));
    monitor.record(key, "ports", ports("up"));
    active = monitor.snapshot([firewall]).alerts.filter(alert => !alert.resolved);
    assert.equal(active.some(alert => alert.kind === "online" || alert.kind === "ports"), false);
  });
});

test("confirms VPN loss on two samples and recovers independently of system failures", async () => {
  await withMonitor(async (monitor, { advance }) => {
    const scope = JSON.stringify([firewall.organizationId, firewall.siteId]);
    const payload = status => ({ ok: true, data: normalizeVpn({ sites: [{ siteId: "peer", tunnel: [{ status }] }] }) });
    monitor.record(scope, "vpn", payload("down"));
    advance(60_000);
    monitor.record(scope, "vpn", payload("down"));
    monitor.record(firewallKey(firewall), "system", { ok: false, error: "HTTP_403" });
    assert.equal(monitor.snapshot([firewall]).alerts.filter(alert => !alert.resolved && ["system", "vpn"].includes(alert.kind)).length, 2);
    advance(60_000);
    monitor.record(scope, "vpn", payload("up"));
    assert.ok(monitor.snapshot([firewall]).alerts.find(alert => alert.message.includes("coupé")).resolved);
  });
});