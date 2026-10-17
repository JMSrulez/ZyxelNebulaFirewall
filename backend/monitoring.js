import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";

export const RETENTION_MS = 48 * 60 * 60 * 1000;
export const INTERVALS = { vpn: 60_000, online: 60_000, system: 300_000, ports: 300_000, interfaces: 300_000 };
const STALE_MS = { vpn: 180_000, online: 180_000, system: 720_000, ports: 720_000, interfaces: 720_000 };

export function firewallKey(firewall) {
  return JSON.stringify([firewall.organizationId, firewall.siteId, firewall.id]);
}

function siteKey(firewall) {
  return JSON.stringify([firewall.organizationId, firewall.siteId]);
}

function percentage(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null;
}

export function normalizeSystem(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("INVALID_RESPONSE");
  return {
    cpu: percentage(body.cpuUsage),
    ram: percentage(body.memUsage),
    sessions: Number.isSafeInteger(body.sessions) && body.sessions >= 0 ? body.sessions : null,
  };
}

export function normalizeVpn(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("INVALID_RESPONSE");
  const tunnels = [];
  const state = (value) => {
    const status = typeof value === "string" ? value.trim().toLowerCase() : "";
    if (["up", "connected", "online", "established"].includes(status)) return "up";
    if (["down", "disconnected", "offline"].includes(status)) return "down";
    return "unknown";
  };
  let known = false;
  for (const group of ["sites", "gateways", "remoteAps"]) {
    if (!(group in body)) continue;
    if (body[group] !== null && !Array.isArray(body[group])) throw new Error("INVALID_RESPONSE");
    known = true;
    for (const peer of body[group] ?? []) {
      if (!peer || typeof peer !== "object") throw new Error("INVALID_RESPONSE");
      const entries = group === "remoteAps" ? [peer] : peer.tunnel;
      if (!Array.isArray(entries)) throw new Error("INVALID_RESPONSE");
      const values = entries.length ? entries : [null];
      values.forEach((tunnel, index) => tunnels.push({
        id: `${group}:${peer.siteId ?? peer.peer ?? peer.devId ?? "?"}:${index}`,
        peer: peer.siteId ?? peer.peer ?? peer.devId ?? "Non identifié",
        state: state(tunnel?.status),
        uptime: typeof tunnel?.uptime === "number" ? tunnel.uptime : null,
        lastHeartbeat: typeof tunnel?.lastHeartbeat === "number" ? tunnel.lastHeartbeat : null,
      }));
    }
  }
  if (!known) throw new Error("INVALID_RESPONSE");
  return { tunnels };
}

export function normalizeOnline(body) {
  if (!Array.isArray(body)) throw new Error("INVALID_RESPONSE");
  return body.map(device => {
    if (!device || typeof device !== "object" || typeof device.devId !== "string") throw new Error("INVALID_RESPONSE");
    const status = typeof device.currentStatus === "string" ? device.currentStatus.toLowerCase() : "";
    return {
      id: device.devId,
      status: status === "online" ? "online" : status === "offline" ? "offline" : "unknown",
    };
  });
}

export function normalizePorts(body) {
  if (!Array.isArray(body)) throw new Error("INVALID_RESPONSE");
  return {
    ports: body.map(port => {
      if (!port || typeof port !== "object") throw new Error("INVALID_RESPONSE");
      const speed = typeof port.linkSpeed === "string" ? port.linkSpeed.trim() : "";
      const down = /^(down|no\s*link|disconnected|offline)$/i.test(speed);
      const up = Boolean(speed) && !/^(unknown|n\/?a|auto|--)$/i.test(speed);
      return {
        portNumber: typeof port.portNumber === "string" ? port.portNumber : null,
        portGroup: typeof port.portGroup === "string" ? port.portGroup : null,
        linkSpeed: speed || null,
        linkState: down ? "down" : up ? "up" : "unknown",
      };
    }),
  };
}

export function normalizeInterfaces(body) {
  if (!body || typeof body !== "object" || Array.isArray(body) || !Array.isArray(body.wan) || !Array.isArray(body.lan)) {
    throw new Error("INVALID_RESPONSE");
  }
  const normalize = item => {
    if (!item || typeof item !== "object") throw new Error("INVALID_RESPONSE");
    return {
      name: typeof item.interface === "string" ? item.interface : null,
      portGroupId: item.portGroupId == null ? null : String(item.portGroupId),
      enabled: typeof item.enabled === "boolean" ? item.enabled : null,
      hasAddress: typeof item.ipv4Address === "string" && item.ipv4Address.length > 0,
      hasGateway: typeof item.ipv4Gateway === "string" && item.ipv4Gateway.length > 0,
    };
  };
  return { wan: body.wan.map(normalize), lan: body.lan.map(normalize) };
}

export class Monitoring {
  constructor({ dataDir, env = process.env, fetchImpl = fetch, now = Date.now }) {
    mkdirSync(dataDir, { recursive: true });
    this.db = new DatabaseSync(path.join(dataDir, "monitoring.sqlite"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS samples (
        id INTEGER PRIMARY KEY, scope TEXT NOT NULL, kind TEXT NOT NULL,
        time INTEGER NOT NULL, payload TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS samples_lookup ON samples(scope, kind, time DESC, id DESC);
      CREATE INDEX IF NOT EXISTS samples_time ON samples(time);
      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY, alert_key TEXT NOT NULL, scope TEXT NOT NULL,
        kind TEXT NOT NULL, message TEXT NOT NULL, opened INTEGER NOT NULL,
        updated INTEGER NOT NULL, resolved INTEGER
      );
      CREATE UNIQUE INDEX IF NOT EXISTS active_alert ON alerts(alert_key) WHERE resolved IS NULL;
    `);
    this.env = env;
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.next = Object.fromEntries(Object.keys(INTERVALS).map(kind => [kind, 0]));
    this.retryAt = 0;
    this.running = null;
  }

  close() { this.db.close(); }

  purge(time = this.now()) {
    this.db.prepare("DELETE FROM samples WHERE time < ?").run(time - RETENTION_MS);
    this.db.prepare("DELETE FROM alerts WHERE COALESCE(resolved, updated) < ?").run(time - RETENTION_MS);
  }

  latest(scope, kind) {
    const row = this.db.prepare("SELECT time, payload FROM samples WHERE scope = ? AND kind = ? ORDER BY time DESC, id DESC LIMIT 1").get(scope, kind);
    return row ? { time: row.time, ...JSON.parse(row.payload) } : null;
  }

  condition(key, scope, kind, message, active, time) {
    if (active) {
      this.db.prepare(`INSERT INTO alerts(alert_key, scope, kind, message, opened, updated)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(alert_key) WHERE resolved IS NULL
        DO UPDATE SET updated = excluded.updated, message = excluded.message`).run(key, scope, kind, message, time, time);
    } else {
      this.db.prepare("UPDATE alerts SET resolved = ?, updated = ? WHERE alert_key = ? AND resolved IS NULL").run(time, time, key);
    }
  }

  record(scope, kind, payload, time = this.now()) {
    const previous = this.latest(scope, kind);
    this.db.exec("BEGIN");
    try {
      this.db.prepare("INSERT INTO samples(scope, kind, time, payload) VALUES (?, ?, ?, ?)").run(scope, kind, time, JSON.stringify(payload));
      const prefix = `${kind}:${scope}`;
      const labels = { vpn: "VPN", online: "cloud", system: "système", ports: "ports", interfaces: "interfaces WAN" };
      this.condition(`${prefix}:collection`, scope, kind, `Collecte ${labels[kind] ?? kind} impossible (${payload.error ?? "erreur"}).`, !payload.ok, time);
      if (payload.ok) {
        const consecutive = previous?.ok && time - previous.time <= STALE_MS[kind];
        if (kind === "system") {
          for (const metric of ["cpu", "ram"]) {
            this.condition(`${prefix}:${metric}`, scope, kind, `${metric.toUpperCase()} ≥ 90 % sur deux mesures.`,
              Boolean(consecutive && payload.data[metric] >= 90 && previous.data[metric] >= 90), time);
          }
          this.condition(`${prefix}:unknown`, scope, kind, "Certaines métriques système sont indisponibles.",
            Object.values(payload.data).some(value => value === null), time);
        } else if (kind === "vpn") {
          const down = payload.data.tunnels.filter(tunnel => tunnel.state === "down");
          const confirmed = consecutive && down.some(tunnel => previous.data.tunnels.some(old => old.id === tunnel.id && old.state === "down"));
          this.condition(`${prefix}:down`, scope, kind, "Un tunnel VPN est coupé sur deux mesures.", Boolean(confirmed), time);
          this.condition(`${prefix}:unknown`, scope, kind, "État de tunnel VPN inconnu.", payload.data.tunnels.some(tunnel => tunnel.state === "unknown"), time);
        } else if (kind === "online") {
          this.condition(`${prefix}:offline`, scope, kind, "Pare-feu hors ligne de Nebula sur deux mesures.",
            Boolean(consecutive && payload.data.status === "offline" && previous.data.status === "offline"), time);
          this.condition(`${prefix}:unknown`, scope, kind, "État cloud du pare-feu indisponible.", payload.data.status === "unknown", time);
        } else if (kind === "ports") {
          const interfaces = this.latest(scope, "interfaces");
          const wanGroups = new Set((interfaces?.data?.wan ?? [])
            .filter(item => item.enabled === true && item.portGroupId !== null)
            .map(item => item.portGroupId));
          const wanPorts = payload.data.ports.filter(port => wanGroups.has(port.portGroup));
          const previousWanPorts = (previous?.data?.ports ?? []).filter(port => wanGroups.has(port.portGroup));
          const allDown = wanPorts.length > 0 && wanPorts.every(port => port.linkState === "down");
          const previouslyDown = previousWanPorts.length === wanPorts.length && previousWanPorts.length > 0
            && previousWanPorts.every(port => port.linkState === "down");
          this.condition(`${prefix}:wan-down`, scope, kind, "Tous les ports WAN associés sont coupés sur deux mesures.",
            Boolean(consecutive && allDown && previouslyDown), time);
        }
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  async request(endpoint, kind) {
    if (this.now() < this.retryAt) return { ok: false, error: "HTTP_429_PAUSE" };
    try {
      const base = (this.env.NEBULA_API_BASE_URL || "https://api.nebula.zyxel.com").trim().replace(/\/+$/, "").replace(/\/v1\/nebula$/i, "");
      const response = await this.fetchImpl(`${base}/v1/nebula${endpoint}`, {
        headers: { Accept: "application/json", "X-ZyxelNebula-API-Key": this.env.NEBULA_API_KEY },
        signal: AbortSignal.timeout(20_000),
      });
      if (response.status === 429) {
        const retry = response.headers?.get("retry-after");
        const delay = retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry);
        this.retryAt = Math.max(this.now() + 300_000, Number.isFinite(delay) ? (retry && /^\d+$/.test(retry) ? this.now() + delay : delay) : 0);
      }
      if (!response.ok) return { ok: false, error: `HTTP_${response.status}` };
      const body = await response.json();
      if (Number(body?.status) >= 400) {
        if (Number(body.status) === 429) this.retryAt = this.now() + 300_000;
        return { ok: false, error: `HTTP_${Number(body.status)}` };
      }
      const normalize = {
        vpn: normalizeVpn,
        online: normalizeOnline,
        system: normalizeSystem,
        ports: normalizePorts,
        interfaces: normalizeInterfaces,
      }[kind];
      return { ok: true, data: normalize(body) };
    } catch (error) {
      return { ok: false, error: error.message === "INVALID_RESPONSE" ? "INVALID_RESPONSE" : error.name === "TimeoutError" ? "TIMEOUT" : "NETWORK_OR_JSON" };
    }
  }

  tick(firewalls) {
    if (!this.running) {
      this.running = this.collect(firewalls).finally(() => { this.running = null; });
    }
    return this.running;
  }

  async collect(firewalls) {
    this.purge();
    if (!this.env.NEBULA_API_KEY || this.now() < this.retryAt) return;
    const assigned = firewalls.filter(firewall => firewall.siteId && firewall.id);
    const siteGroups = new Map();
    for (const firewall of assigned) {
      const key = siteKey(firewall);
      if (!siteGroups.has(key)) siteGroups.set(key, []);
      siteGroups.get(key).push(firewall);
    }
    for (const kind of Object.keys(INTERVALS)) {
      if (this.now() < this.next[kind]) continue;
      const siteScoped = kind === "vpn" || kind === "online";
      const targetGroups = siteScoped ? [...siteGroups.values()] : assigned.map(firewall => [firewall]);
      for (const group of targetGroups) {
        const firewall = group[0];
        const suffix = {
          vpn: "/vpn-status",
          online: "/online-status",
          system: `/gw/${encodeURIComponent(firewall.id)}/system-status`,
          ports: `/gw/${encodeURIComponent(firewall.id)}/ports-status`,
          interfaces: `/gw/${encodeURIComponent(firewall.id)}/interface-settings`,
        }[kind];
        const payload = await this.request(`/${encodeURIComponent(firewall.siteId)}${suffix}`, kind);
        if (kind === "online") {
          for (const device of group) {
            const status = payload.ok ? payload.data.find(item => item.id === device.id)?.status ?? "unknown" : null;
            this.record(firewallKey(device), kind, payload.ok ? { ok: true, data: { status } } : payload);
          }
        } else {
          this.record(kind === "vpn" ? siteKey(firewall) : firewallKey(firewall), kind, payload);
        }
      }
      if (targetGroups.length) this.next[kind] = this.now() + INTERVALS[kind];
    }
    this.purge();
  }

  snapshot(firewalls) {
    const time = this.now();
    this.purge(time);
    const scopes = new Set();
    const transient = [];
    const devices = firewalls.map(firewall => {
      const key = firewallKey(firewall);
      const result = { key, id: firewall.id, siteId: firewall.siteId, organizationId: firewall.organizationId };
      for (const kind of Object.keys(INTERVALS)) {
        const scope = kind === "vpn" ? siteKey(firewall) : key;
        scopes.add(scope);
        const sample = this.latest(scope, kind);
        const state = !sample ? "pending" : time - sample.time > STALE_MS[kind] ? "stale" : !sample.ok ? "error" : "ok";
        result[kind] = { ...sample, state };
        if (state === "stale" || state === "pending") transient.push({
          id: `${kind}:${scope}:stale`, scope, kind, message: state === "stale" ? "Mesures trop anciennes." : "En attente de collecte.",
          opened: sample?.time ?? null, resolved: null,
        });
      }
      return result;
    });
    const alerts = this.db.prepare("SELECT id, scope, kind, message, opened, updated, resolved FROM alerts ORDER BY updated DESC LIMIT 500").all()
      .filter(alert => scopes.has(alert.scope));
    const deduplicated = [...new Map(transient.map(alert => [alert.id, alert])).values()];
    return { devices, alerts: [...deduplicated, ...alerts], retryAt: this.retryAt || null, retentionHours: 48, intervals: INTERVALS, generatedAt: time };
  }

  history(key, kind = "system") {
    this.purge();
    return this.db.prepare("SELECT time, payload FROM samples WHERE scope = ? AND kind = ? ORDER BY time, id").all(key, kind)
      .map(row => ({ time: row.time, ...JSON.parse(row.payload) }));
  }
}