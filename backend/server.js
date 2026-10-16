import { createServer } from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { NebulaApiError, scanInventory } from "./inventory.js";

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
  if (error.status === 401) return { status: 502, message: "La clé API Nebula est invalide." };
  if (error.status === 403) return { status: 502, message: "La clé API n'a pas accès à ces données." };
  if (error.status === 429) return { status: 502, message: "Limite d'appels Nebula atteinte. Réessayez plus tard." };
  return { status: 502, message: "Le scan Nebula a échoué. L'inventaire précédent est conservé." };
}

export function createApiServer({
  env = process.env,
  dataDir = env.DATA_DIR || DEFAULT_DATA_DIR,
  fetchImpl = fetch,
} = {}) {
  let activeScan;

  return createServer(async (request, response) => {
    const requestUrl = new URL(request.url, "http://localhost");

    if (request.method === "GET" && requestUrl.pathname === "/api/health") {
      return sendJson(response, 200, { status: "ok" });
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
          await writeCache(dataDir, inventory);
          return inventory;
        }).finally(() => {
          activeScan = undefined;
        });

        const inventory = await activeScan;
        return sendJson(response, 200, { ...inventory, configured: true });
      } catch (error) {
        const failure = apiErrorMessage(error);
        return sendJson(response, failure.status, { message: failure.message });
      }
    }

    return sendJson(response, 404, { message: "Route introuvable." });
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  const server = createApiServer();
  server.listen(port, "0.0.0.0", () => {
    console.log(`Nebula inventory API listening on port ${port}`);
  });
}