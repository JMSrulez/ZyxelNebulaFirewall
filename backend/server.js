import { createServer } from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { NebulaApiError, scanInventory } from "./inventory.js";
import { Monitoring, firewallKey } from "./monitoring.js";

const DEFAULT_DATA_DIR = "/data";
const CACHE_FILE = "inventory.json";

async function readCache(dataDir) {
  try {
    return JSON.parse(await readFile(path.join(dataDir, CACHE_FILE), "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeCache(dataDir, inventory) {
  await mkdir(dataDir, { recursive: true });
  const cachePath = path.join(dataDir, CACHE_FILE);
  const temporaryPath = `${cachePath}.${randomUUID()}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(inventory, null, 2)}\n`, { mode: 0o600 });
  await rename(temporaryPath, cachePath);
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

function apiErrorMessage(error) {
  if (error.code === "API_KEY_MISSING") {
    return { status: 503, message: "La clé API Nebula n'est pas configurée." };
  }
  if (error.code === "CACHE_WRITE_FAILED") {
    return { status: 500, message: "Impossible d'enregistrer l'inventaire local. Vérifiez les permissions et l'espace disque du volume /data." };
  }
  if (error.status === 401) return { status: 502, message: "La clé API Nebula est invalide." };
  if (error.status === 403) return { status: 502, message: "La clé API n'a pas accès à ces données." };
  if (error.status === 429) return { status: 502, message: "Limite d'appels Nebula atteinte. Réessayez plus tard." };
  return { status: 502, message: "Le scan Nebula a échoué. L'inventaire précédent est conservé." };
}

export function createApiServer({
  env = process.env,
  dataDir = env.DATA_DIR || DEFAULT_DATA_DIR,
  fetchImpl = fetch,
  logger = console,
  monitoringEnabled = false,
  now = Date.now,
} = {}) {
  let activeScan;
  let monitoring;
  let timer;
  let stopped = false;
  const getMonitoring = () => monitoring ??= new Monitoring({ dataDir, env, fetchImpl, now });

  async function pollMonitoring() {
    try {
      const inventory = await readCache(dataDir);
      if (!stopped) await getMonitoring().tick(inventory?.firewalls ?? []);
    } catch (error) {
      logger.error("Nebula monitoring failed", { code: error.code ?? error.name });
    }
  }

  const server = createServer(async (request, response) => {
    const requestUrl = new URL(request.url, "http://localhost");

    if (request.method === "GET" && requestUrl.pathname === "/api/health") {
      return sendJson(response, 200, { status: "ok" });
    }

    if (request.method === "GET" && ["/api/monitoring", "/api/monitoring/history"].includes(requestUrl.pathname)) {
      try {
        const inventory = await readCache(dataDir);
        const firewalls = inventory?.firewalls ?? [];
        const monitor = getMonitoring();
        if (requestUrl.pathname.endsWith("/history")) {
          const key = requestUrl.searchParams.get("key");
          const firewall = firewalls.find(device => firewallKey(device) === key);
          if (!firewall) return sendJson(response, 404, { message: "Pare-feu introuvable." });
          return sendJson(response, 200, {
            system: monitor.history(key),
            vpn: monitor.history(JSON.stringify([firewall.organizationId, firewall.siteId]), "vpn"),
            online: monitor.history(key, "online"),
            ports: monitor.history(key, "ports"),
            interfaces: monitor.history(key, "interfaces"),
          });
        }
        return sendJson(response, 200, monitor.snapshot(firewalls));
      } catch (error) {
        logger.error("Nebula monitoring storage failed", { code: error.code ?? error.name });
        return sendJson(response, 503, { message: "Supervision indisponible. Vérifiez les permissions et l'espace disque du volume /data." });
      }
    }

    if (request.method === "GET" && requestUrl.pathname === "/api/inventory") {
      try {
        const cachedInventory = await readCache(dataDir);
        return sendJson(response, 200, {
          configured: Boolean(env.NEBULA_API_KEY),
          scannedAt: cachedInventory?.scannedAt ?? null,
          firewalls: cachedInventory?.firewalls ?? [],
        });
      } catch {
        return sendJson(response, 500, { message: "Le cache local est illisible." });
      }
    }

    if (request.method === "POST" && requestUrl.pathname === "/api/scan") {
      if (!env.NEBULA_API_KEY) {
        return sendJson(response, 503, { message: "La clé API Nebula n'est pas configurée." });
      }

      try {
        activeScan ??= scanInventory({
          apiKey: env.NEBULA_API_KEY,
          apiBaseUrl: env.NEBULA_API_BASE_URL,
          fetchImpl,
        }).then(async (firewalls) => {
          const inventory = { scannedAt: new Date().toISOString(), firewalls };
          try {
            await writeCache(dataDir, inventory);
          } catch (cause) {
            const error = new Error("Inventory cache write failed", { cause });
            error.code = "CACHE_WRITE_FAILED";
            throw error;
          }
          if (monitoringEnabled && !stopped) void pollMonitoring();
          return inventory;
        }).finally(() => {
          activeScan = undefined;
        });

        const inventory = await activeScan;
        return sendJson(response, 200, { ...inventory, configured: true });
      } catch (error) {
        logger.error("Nebula scan failed", {
          code: error.code ?? error.name,
          causeCode: error.cause?.code ?? null,
          status: error.status ?? null,
        });
        const failure = apiErrorMessage(error);
        return sendJson(response, failure.status, { message: failure.message });
      }
    }

    return sendJson(response, 404, { message: "Route introuvable." });
  });
  server.on("listening", () => {
    if (!monitoringEnabled) return;
    void pollMonitoring();
    timer = setInterval(() => { void pollMonitoring(); }, 15_000);
    timer.unref();
  });
  server.on("close", () => {
    stopped = true;
    clearInterval(timer);
    if (monitoring?.running) void monitoring.running.finally(() => monitoring.close()).catch(() => {});
    else monitoring?.close();
  });
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  const server = createApiServer({ monitoringEnabled: true });
  server.listen(port, "0.0.0.0", () => {
    console.log(`Nebula inventory API listening on port ${port}`);
  });
  process.once("SIGTERM", () => server.close());
  process.once("SIGINT", () => server.close());
}