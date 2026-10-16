import test from "node:test";
import assert from "node:assert/strict";
import { isFirewall, scanInventory } from "./inventory.js";

test("identifies Nebula gateways and firewall model names", () => {
  assert.equal(isFirewall({ deviceType: "GW" }), true);
  assert.equal(isFirewall({ type: "FIREWALL" }), true);
  assert.equal(isFirewall({ modelName: "USG FLEX 200" }), true);
  assert.equal(isFirewall({ deviceType: "AP", modelName: "WAX650S" }), false);
});

test("scans organizations and attaches site metadata to firewalls only", async () => {
  const requested = [];
  const responses = new Map([
    ["/v1/nebula/organizations", [{ orgId: "org/1", name: "Main org" }]],
    ["/v1/nebula/organizations/org%2F1/sites", [{ siteId: "site-1", name: "HQ" }]],
    ["/v1/nebula/organizations/org%2F1/sites/devices", [{
      siteId: "site-1",
      devices: [
        { devId: "fw-1", deviceType: "GW", model: "USG FLEX 200" },
        { devId: "ap-1", deviceType: "AP", model: "WAX650S" },
      ],
    }]],
  ]);

  const firewalls = await scanInventory({
    apiKey: "test-key",
    apiBaseUrl: "https://api.nebula.zyxel.com/v1/nebula/",
    fetchImpl: async (url, options) => {
      const path = new URL(url).pathname;
      requested.push(path);
      assert.equal(options.headers["X-ZyxelNebula-API-Key"], "test-key");
      return { ok: true, json: async () => responses.get(path) };
    },
  });

  assert.deepEqual(firewalls, [{
    id: "fw-1",
    name: null,
    model: "USG FLEX 200",
    serialNumber: null,
    macAddress: null,
    organizationId: "org/1",
    organizationName: "Main org",
    siteId: "site-1",
    siteName: "HQ",
  }]);
  assert.equal(requested.length, 3);
});

test("refuses a scan when the API key is missing", async () => {
  await assert.rejects(scanInventory({ apiKey: "" }), { code: "API_KEY_MISSING" });
});

test("reports a clear error when Nebula returns HTML instead of JSON", async () => {
  await assert.rejects(
    scanInventory({
      apiKey: "test-key",
      fetchImpl: async () => ({
        ok: true,
        json: async () => { throw new SyntaxError("Unexpected token '<'"); },
      }),
    }),
    { code: "INVALID_API_RESPONSE" },
  );
});