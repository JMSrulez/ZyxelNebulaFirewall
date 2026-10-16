const FIREWALL_TYPES = new Set(["FIREWALL", "GW", "GATEWAY", "SECURE_GATEWAY"]);
const TYPE_FIELDS = ["deviceType", "type", "device_type", "productType", "category"];
const MODEL_FIELDS = ["model", "modelName", "productName", "deviceModel"];

export class NebulaApiError extends Error {
  constructor(status) {
    super(`Nebula API returned HTTP ${status}`);
    this.name = "NebulaApiError";
    this.status = status;
  }
}

export function isFirewall(device) {
  const type = TYPE_FIELDS
    .map((field) => device[field])
    .filter((value) => typeof value === "string")
    .some((value) => FIREWALL_TYPES.has(value.toUpperCase().replace(/[ -]/g, "_")));

  if (type) return true;

  return MODEL_FIELDS
    .map((field) => device[field])
    .filter((value) => typeof value === "string")
    .some((value) => /^(NSG|USG|USG FLEX|USG FLEX H|ATP|SCR)\b/i.test(value.trim()));
}

function firstValue(source, fields) {
  for (const field of fields) {
    if (source[field] !== undefined && source[field] !== null && source[field] !== "") {
      return source[field];
    }
  }
  return null;
}

function normalizeFirewall(device, organization, site) {
  return {
    id: firstValue(device, ["devId", "deviceId", "id"]),
    name: firstValue(device, ["name", "deviceName", "hostname"]),
    model: firstValue(device, MODEL_FIELDS),
    serialNumber: firstValue(device, ["serialNumber", "serial", "sn"]),
    macAddress: firstValue(device, ["macAddress", "mac"]),
    organizationId: organization.orgId,
    organizationName: organization.name,
    siteId: site.siteId,
    siteName: site.name ?? site.siteId,
  };
}

async function getJson(fetchImpl, baseUrl, path, apiKey) {
  const response = await fetchImpl(`${baseUrl}${path}`, {
    headers: {
      Accept: "application/json",
      "X-ZyxelNebula-API-Key": apiKey,
    },
    signal: AbortSignal.timeout(20_000),
  });

  if (!response.ok) throw new NebulaApiError(response.status);

  const body = await response.json();
  if (!Array.isArray(body) && Number(body?.status) >= 400) {
    throw new NebulaApiError(Number(body.status));
  }
  return body;
}

export async function scanInventory({
  apiKey,
  apiBaseUrl = "https://api.nebula.zyxel.com",
  fetchImpl = fetch,
}) {
  if (!apiKey) {
    const error = new Error("Nebula API key is not configured");
    error.code = "API_KEY_MISSING";
    throw error;
  }

  const baseUrl = apiBaseUrl.replace(/\/$/, "");
  const organizations = await getJson(fetchImpl, baseUrl, "/v1/nebula/organizations", apiKey);
  const firewalls = [];

  for (const organization of organizations) {
    const [sites, devicesBySite] = await Promise.all([
      getJson(
        fetchImpl,
        baseUrl,
        `/v1/nebula/organizations/${encodeURIComponent(organization.orgId)}/sites`,
        apiKey,
      ),
      getJson(
        fetchImpl,
        baseUrl,
        `/v1/nebula/organizations/${encodeURIComponent(organization.orgId)}/sites/devices`,
        apiKey,
      ),
    ]);

    const sitesById = new Map(sites.map((site) => [site.siteId, site]));
    for (const siteDevices of devicesBySite) {
      const site = sitesById.get(siteDevices.siteId) ?? { siteId: siteDevices.siteId };
      for (const device of siteDevices.devices ?? []) {
        if (isFirewall(device)) {
          firewalls.push(normalizeFirewall(device, organization, site));
        }
      }
    }
  }

  return firewalls;
}