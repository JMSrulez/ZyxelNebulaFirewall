import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApiServer } from "./server.js";
import { Monitoring, firewallKey } from "./monitoring.js";

async function withServer(run, options = {}) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "nebula-cache-"));
  const server = createApiServer({ dataDir, ...options });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  try {
    await run(`http://127.0.0.1:${address.port}`, dataDir);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(dataDir, { recursive: true, force: true });
  }
}

test("serves cached inventory without contacting Nebula", async () => {
  let apiCalls = 0;
  await withServer(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/inventory`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      configured: true,
      scannedAt: null,
      firewalls: [],
    });
    assert.equal(apiCalls, 0);
  }, { env: { NEBULA_API_KEY: "configured" }, fetchImpl: async () => { apiCalls += 1; } });
});

test("distinguishes cache write failures without logging credentials", async () => {
  const logs = [];
  await withServer(async (baseUrl, dataDir) => {
    await mkdir(path.join(dataDir, "inventory.json"));
    const response = await fetch(`${baseUrl}/api/scan`, { method: "POST" });
    assert.equal(response.status, 500);
    assert.match((await response.json()).message, /volume \/data/);
    assert.equal(logs.length, 1);
    assert.equal(logs[0][1].code, "CACHE_WRITE_FAILED");
    assert.ok(logs[0][1].causeCode);
    assert.equal(JSON.stringify(logs).includes("secret-test-key"), false);
  }, {
    env: { NEBULA_API_KEY: "secret-test-key" },
    fetchImpl: async () => ({ ok: true, json: async () => [] }),
    logger: { error: (...entry) => logs.push(entry) },
  });
});

test("writes cache only after a complete successful scan", async () => {
  let shouldFail = false;
  const apiResponses = new Map([
    ["/v1/nebula/organizations", [{ orgId: "org-1", name: "Org" }]],
    ["/v1/nebula/organizations/org-1/sites", [{ siteId: "site-1", name: "HQ" }]],
    ["/v1/nebula/organizations/org-1/sites/devices", [{
      siteId: "site-1",
      devices: [{ devId: "fw-1", deviceType: "GW", model: "USG FLEX 200" }],
    }]],
  ]);

  await withServer(async (baseUrl, dataDir) => {
    const firstScan = await fetch(`${baseUrl}/api/scan`, { method: "POST" });
    assert.equal(firstScan.status, 200);
    const firstInventory = await firstScan.json();
    assert.equal(firstInventory.firewalls[0].id, "fw-1");
    assert.ok(firstInventory.scannedAt);

    const cacheBeforeFailure = await readFile(path.join(dataDir, "inventory.json"), "utf8");
    shouldFail = true;
    const cachedResponse = await fetch(`${baseUrl}/api/inventory`);
    const cachedInventory = await cachedResponse.json();
    assert.equal(cachedResponse.status, 200);
    assert.equal(cachedInventory.scannedAt, firstInventory.scannedAt);
    assert.equal(cachedInventory.firewalls[0].id, "fw-1");

    const failedScan = await fetch(`${baseUrl}/api/scan`, { method: "POST" });
    assert.equal(failedScan.status, 502);
    assert.equal(await readFile(path.join(dataDir, "inventory.json"), "utf8"), cacheBeforeFailure);
  }, {
    env: { NEBULA_API_KEY: "configured" },
    fetchImpl: async (url) => {
      if (shouldFail) return { ok: false, status: 503 };
      const body = apiResponses.get(new URL(url).pathname);
      return { ok: true, json: async () => body };
    },
  });
});

test("serves monitoring and 48h history without upstream calls or exposing credentials", async () => {
  await withServer(async (baseUrl, dataDir) => {
    const firewall = { id: "fw1", siteId: "site1", organizationId: "org1" };
    await writeFile(path.join(dataDir, "inventory.json"), JSON.stringify({ firewalls: [firewall] }));
    const monitor = new Monitoring({ dataDir });
    monitor.record(firewallKey(firewall), "system", { ok: true, data: { cpu: 20, ram: 30, sessions: 0 } });
    monitor.record(JSON.stringify(["org1", "site1"]), "vpn", { ok: true, data: { tunnels: [] } });
    monitor.close();
    const response = await fetch(`${baseUrl}/api/monitoring`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.retentionHours, 48);
    assert.equal(body.devices[0].system.data.sessions, 0);
    assert.equal(body.devices[0].vpn.state, "ok");
    assert.equal(JSON.stringify(body).includes("secret-key"), false);
    const history = await fetch(`${baseUrl}/api/monitoring/history?key=${encodeURIComponent(firewallKey(firewall))}`);
    const samples = await history.json();
    assert.equal(samples.system.length, 1);
    assert.equal(samples.vpn.length, 1);
    assert.equal((await fetch(`${baseUrl}/api/monitoring/history?key=unknown`)).status, 404);
  }, { env: { NEBULA_API_KEY: "secret-key" }, fetchImpl: async () => { assert.fail("Unexpected upstream call"); } });
});