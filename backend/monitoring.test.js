import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { Monitoring, RETENTION_MS, firewallKey, normalizeSystem, normalizeVpn } from "./monitoring.js";

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
      return { ok: true, json: async () => url.endsWith("vpn-status")
        ? { sites: [{ siteId: "remote", tunnel: [{ status: "up" }] }] }
        : { cpuUsage: 20, memUsage: 40, sessions: 0 } };
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

test("collects once per site, independently schedules system and VPN, and persists", async () => {
  await withMonitor(async (monitor, { requests, advance, options }) => {
    const devices = [firewall, { ...firewall, id: "fw2" }];
    await Promise.all([monitor.tick(devices), monitor.tick(devices)]);
    assert.equal(requests.length, 3);
    assert.ok(requests.some(url => url.includes("site%2F1/gw/fw%2F1")));
    advance(60_000);
    await monitor.tick(devices);
    assert.equal(requests.length, 4);
    const reopened = new Monitoring(options);
    try {
      assert.equal(reopened.snapshot(devices).devices[0].system.data.sessions, 0);
      assert.equal(reopened.history(firewallKey(firewall)).length, 1);
    } finally { reopened.close(); }
    advance(240_000);
    await monitor.tick(devices);
    assert.equal(requests.length, 7);
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

test("confirms VPN loss on two samples and recovers independently of system failures", async () => {
  await withMonitor(async (monitor, { advance }) => {
    const scope = JSON.stringify([firewall.organizationId, firewall.siteId]);
    const payload = status => ({ ok: true, data: normalizeVpn({ sites: [{ siteId: "peer", tunnel: [{ status }] }] }) });
    monitor.record(scope, "vpn", payload("down"));
    advance(60_000);
    monitor.record(scope, "vpn", payload("down"));
    monitor.record(firewallKey(firewall), "system", { ok: false, error: "HTTP_403" });
    assert.equal(monitor.snapshot([firewall]).alerts.filter(alert => !alert.resolved).length, 2);
    advance(60_000);
    monitor.record(scope, "vpn", payload("up"));
    assert.ok(monitor.snapshot([firewall]).alerts.find(alert => alert.message.includes("coupé")).resolved);
  });
});