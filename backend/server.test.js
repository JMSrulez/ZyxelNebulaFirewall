import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createApiServer } from "./server.js";

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