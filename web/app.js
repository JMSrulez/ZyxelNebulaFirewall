const { t } = NebulaI18n;
const elements = {
  scanButton: document.querySelector("#scan-button"),
  notice: document.querySelector("#notice"),
  firewallCount: document.querySelector("#firewall-count"),
  organizationCount: document.querySelector("#organization-count"),
  siteCount: document.querySelector("#site-count"),
  scannedAt: document.querySelector("#scanned-at"),
  monitoringStatus: document.querySelector("#monitoring-status"),
  alertCount: document.querySelector("#alert-count"),
  alertList: document.querySelector("#alert-list"),
  historyDevice: document.querySelector("#history-device"),
  historyKind: document.querySelector("#history-kind"),
  historyCaption: document.querySelector("#history-caption"),
  historyChart: document.querySelector("#history-chart"),
  filterInput: document.querySelector("#filter-input"),
  rows: document.querySelector("#firewall-rows"),
  emptyState: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyDetail: document.querySelector("#empty-detail"),
  visibleCount: document.querySelector("#visible-count"),
};

let inventory = { firewalls: [], scannedAt: null };
let monitoring = { devices: [], alerts: [], generatedAt: null };
let historyCache = { key: null, loadedAt: 0, value: null };
let noticeMessage = "";
let monitoringError = "";

function showNotice(message) {
  noticeMessage = message;
  elements.notice.textContent = t(message);
  elements.notice.hidden = !message;
}

function formattedDate(value) {
  if (!value) return t("Jamais");
  return new Intl.DateTimeFormat(NebulaI18n.language === "fr" ? "fr-FR" : "en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function makeCell(value, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value || "—";
  return cell;
}

function addDeviceCell(row, firewall) {
  const cell = document.createElement("td");
  const name = document.createElement("span");
  name.className = "device-name";
  name.textContent = firewall.name || firewall.model || t("Pare-feu Zyxel");
  const id = document.createElement("span");
  id.className = "device-id";
  id.textContent = firewall.id || t("Identifiant indisponible");
  cell.append(name, id);
  row.append(cell);
}

function addSerialCell(row, firewall) {
  const cell = document.createElement("td");
  const serial = document.createElement("span");
  serial.className = "serial-value";
  serial.textContent = firewall.serialNumber || firewall.macAddress || "—";
  cell.append(serial);
  row.append(cell);
}

function monitoringLabel(state) {
  return t(({
    ok: "À jour",
    pending: "En attente",
    stale: "Ancienne",
    error: "Erreur",
  })[state] || "Inconnue");
}

function addMetricCell(row, value, state, unit = "") {
  const cell = document.createElement("td");
  const badge = document.createElement("span");
  const available = value !== null && value !== undefined;
  const displayState = available ? state : state === "ok" ? "stale" : state;
  const displayValue = typeof value === "number" && !Number.isInteger(value) ? Number(value.toFixed(1)) : value;
  badge.className = `monitor-value monitor-value--${displayState || "pending"}`;
  badge.textContent = available ? `${displayValue}${unit}` : state === "ok" ? t("Indisponible") : monitoringLabel(state);
  cell.append(badge);
  row.append(cell);
}

function formattedUptime(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return t("Indisponible");
  const minutes = Math.floor(seconds / 60);
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const remainder = minutes % 60;
  if (days) return t("{days} j {hours} h", { days, hours });
  if (hours) return `${hours} h ${remainder} min`;
  return `${remainder} min`;
}

function heartbeatDate(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return null;
  const milliseconds = value < 100_000_000_000 ? value * 1000 : value;
  const date = new Date(milliseconds);
  return Number.isNaN(date.getTime()) ? null : date;
}

function addVpnCell(row, sample) {
  const tunnels = sample?.data?.tunnels || [];
  const up = tunnels.filter((tunnel) => tunnel.state === "up").length;
  const down = tunnels.filter((tunnel) => tunnel.state === "down").length;
  const state = sample?.state || "pending";
  let label = monitoringLabel(state);
  let tone = state;
  if (state === "ok") {
    if (!tunnels.length) label = t("Aucun tunnel remonté");
    else if (down) { label = t("{count} actif(s)", { count: `${up}/${tunnels.length}` }); tone = "error"; }
    else if (up === tunnels.length) label = t("{count} actif(s)", { count: up });
    else { label = t("État inconnu"); tone = "stale"; }
  }
  const cell = document.createElement("td");
  cell.className = "vpn-cell";
  const summary = document.createElement("span");
  summary.className = `monitor-value monitor-value--${tone || "pending"}`;
  summary.textContent = label;
  cell.append(summary);
  if (tunnels.length) {
    const list = document.createElement("ul");
    list.className = "vpn-tunnel-list";
    tunnels.forEach((tunnel, index) => {
      const item = document.createElement("li");
      const name = document.createElement("strong");
      name.className = "vpn-tunnel-name";
      name.textContent = tunnel.peer === "Non identifié" ? t("Non identifié") : tunnel.peer || tunnel.name || `Tunnel ${index + 1}`;
      const status = document.createElement("span");
      status.className = `vpn-tunnel-state vpn-tunnel-state--${tunnel.state || "unknown"}`;
      status.textContent = t(tunnel.state === "up" ? "Actif" : tunnel.state === "down" ? "Coupé" : "Inconnu");
      const details = document.createElement("span");
      details.className = "vpn-tunnel-details";
      const heartbeat = heartbeatDate(tunnel.lastHeartbeat);
      details.textContent = `Uptime ${formattedUptime(tunnel.uptime)} · Heartbeat ${heartbeat ? formattedDate(heartbeat) : t("indisponible")}`;
      item.append(name, status, details);
      list.append(item);
    });
    cell.append(list);
  }
  row.append(cell);
}

function addOnlineCell(row, sample) {
  const state = sample?.state || "pending";
  const status = sample?.data?.status;
  const label = state !== "ok"
    ? monitoringLabel(state)
    : t(status === "online" ? "En ligne" : status === "offline" ? "Hors ligne" : "Inconnu");
  const tone = state !== "ok" ? state : status === "online" ? "ok" : status === "offline" ? "error" : "stale";
  addMetricCell(row, label, tone);
}

function addWanCell(row, portsSample, interfacesSample) {
  const cell = document.createElement("td");
  cell.className = "wan-cell";
  const settings = interfacesSample?.data?.wan;
  const ports = portsSample?.data?.ports;
  if (interfacesSample?.state !== "ok") {
    const line = document.createElement("span");
    line.className = `monitor-value monitor-value--${interfacesSample?.state || "pending"}`;
    line.textContent = t("Interfaces : {state}", { state: monitoringLabel(interfacesSample?.state) });
    cell.append(line);
  } else if (!settings?.length) {
    const line = document.createElement("span");
    line.className = "monitor-value monitor-value--stale";
    line.textContent = t("Aucune interface WAN remontée");
    cell.append(line);
  } else {
    const enabledCount = settings.filter(item => item.enabled === true).length;
    const summary = document.createElement("span");
    summary.className = "monitor-value monitor-value--ok";
    summary.textContent = t("{count} interface(s) activée(s)", { count: `${enabledCount}/${settings.length}` });
    cell.append(summary);
    const list = document.createElement("ul");
    list.className = "wan-detail-list";
    for (const setting of settings) {
      const item = document.createElement("li");
      const name = document.createElement("strong");
      name.textContent = setting.name || setting.portGroupId || "WAN";
      const enabled = document.createElement("span");
      enabled.textContent = t(setting.enabled === true ? "Activée" : setting.enabled === false ? "Désactivée" : "État inconnu");
      const address = document.createElement("span");
      address.className = "wan-detail-meta";
      address.textContent = t("IPv4 {address} · passerelle {gateway}", {
        address: t(setting.hasAddress ? "présente" : "non remontée"),
        gateway: t(setting.hasGateway ? "présente" : "non remontée"),
      });
      item.append(name, enabled, address);
      const matchingPorts = (ports || []).filter(port => setting.portGroupId && port.portGroup === setting.portGroupId);
      if (portsSample?.state === "ok" && matchingPorts.length) {
        for (const port of matchingPorts) {
          const link = document.createElement("span");
          link.className = `wan-detail-meta monitor-value--${port.linkState === "up" ? "ok" : port.linkState === "down" ? "error" : "stale"}`;
          link.textContent = `Port ${port.portNumber || "?"} · ${port.linkSpeed || t("lien inconnu")}`;
          item.append(link);
        }
      }
      list.append(item);
    }
    cell.append(list);
  }
  if (portsSample?.state !== "ok") {
    const line = document.createElement("span");
    line.className = `wan-detail-meta monitor-value--${portsSample?.state || "pending"}`;
    line.textContent = t("État des ports : {state}", { state: monitoringLabel(portsSample?.state) });
    cell.append(line);
  }
  row.append(cell);
}

function renderAlerts() {
  const active = monitoring.alerts.filter((alert) => !alert.resolved);
  elements.alertCount.textContent = t(active.length === 1 ? "{count} active" : "{count} actives", { count: active.length });
  elements.alertList.replaceChildren();
  if (!active.length) {
    const item = document.createElement("li");
    item.className = "alert-empty";
    item.textContent = t("Aucune alerte active.");
    elements.alertList.append(item);
    return;
  }
  for (const alert of active.slice(0, 8)) {
    const item = document.createElement("li");
    item.className = `alert-item alert-item--${alert.kind === "vpn" ? "vpn" : "system"}`;
    const message = document.createElement("span");
    message.textContent = t(alert.message);
    const time = document.createElement("time");
    time.textContent = alert.updated ? formattedDate(alert.updated) : t("En attente");
    item.append(message, time);
    elements.alertList.append(item);
  }
}

function renderHistoryOptions() {
  const previous = elements.historyDevice.value;
  elements.historyDevice.replaceChildren();
  for (const device of monitoring.devices) {
    const firewall = inventory.firewalls.find((item) => JSON.stringify([item.organizationId, item.siteId, item.id]) === device.key);
    const option = document.createElement("option");
    option.value = device.key;
    option.textContent = firewall?.name || firewall?.model || device.id;
    elements.historyDevice.append(option);
  }
  if (monitoring.devices.some((device) => device.key === previous)) elements.historyDevice.value = previous;
}

function drawHistory() {
  const canvas = elements.historyChart;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(rect.width * ratio);
  canvas.height = Math.round(rect.height * ratio);
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const width = rect.width;
  const height = rect.height;
  const colors = getComputedStyle(document.documentElement);
  const ink = colors.getPropertyValue("--muted").trim();
  const grid = colors.getPropertyValue("--line").trim();
  const accent = colors.getPropertyValue("--green").trim();
  const key = elements.historyKind.value;
  const historyKind = key === "vpn" ? "vpn" : key === "online" ? "online" : key === "wan" ? "ports" : "system";
  const samples = historyCache.value?.[historyKind] || [];
  const now = monitoring.generatedAt || Date.now();
  const start = now - 48 * 60 * 60 * 1000;
  const left = 48;
  const right = width - 12;
  const top = 14;
  const bottom = height - 28;
  const range = key === "sessions"
    ? Math.max(1, ...samples.map((sample) => sample.ok ? sample.data?.sessions || 0 : 0))
    : 100;
  context.font = "10px 'DM Mono', Consolas, monospace";
  context.textBaseline = "middle";
  context.strokeStyle = grid;
  context.fillStyle = ink;
  context.lineWidth = 1;
  for (const step of [0, 0.5, 1]) {
    const y = bottom - (bottom - top) * step;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(right, y);
    context.stroke();
    context.fillText(key === "sessions" ? String(Math.round(range * step)) : `${Math.round(step * 100)}%`, 5, y);
  }
  const labels = ["48 h", "24 h", t("Maintenant")];
  labels.forEach((label, index) => {
    context.textAlign = index === 0 ? "left" : index === labels.length - 1 ? "right" : "center";
    context.fillText(label, left + (right - left) * index / 2, height - 11);
  });
  context.textAlign = "start";
  const points = [];
  for (const sample of samples) {
    if (!sample.ok || sample.time < start) continue;
    let value;
    if (key === "vpn") {
      const tunnels = sample.data?.tunnels || [];
      if (tunnels.length) value = 100 * tunnels.filter((tunnel) => tunnel.state === "up").length / tunnels.length;
    } else if (key === "online") {
      if (sample.data?.status === "online") value = 100;
      else if (sample.data?.status === "offline") value = 0;
    } else if (key === "wan") {
      const interfaceSample = (historyCache.value?.interfaces || []).filter(item => item.ok && item.time <= sample.time).at(-1);
      const groups = new Set((interfaceSample?.data?.wan || []).filter(item => item.enabled === true && item.portGroupId).map(item => item.portGroupId));
      const ports = (sample.data?.ports || []).filter(port => groups.has(port.portGroup) && ["up", "down"].includes(port.linkState));
      if (ports.length) value = 100 * ports.filter(port => port.linkState === "up").length / ports.length;
    } else if (typeof sample.data?.[key] === "number") value = sample.data[key];
    if (value === undefined) continue;
    points.push({ x: left + (right - left) * (sample.time - start) / (now - start), y: bottom - (bottom - top) * value / range });
  }
  context.strokeStyle = accent;
  context.lineWidth = 2;
  context.beginPath();
  points.forEach((point, index) => {
    if (index === 0 || point.x - points[index - 1].x > (right - left) * 0.08) context.moveTo(point.x, point.y);
    else context.lineTo(point.x, point.y);
  });
  context.stroke();
  if (points.length < 2) {
    context.fillStyle = ink;
    context.textAlign = "center";
    context.fillText(t(points.length ? "Une seule mesure disponible" : "Aucune mesure disponible sur cette période"), width / 2, height / 2, Math.max(1, right - left));
    context.textAlign = "start";
  }
  const sampleLabel = t(key === "vpn" ? "Tunnels actifs" : key === "online" ? "Disponibilité cloud" : key === "wan" ? "Liens WAN actifs" : key === "sessions" ? "Sessions" : `${key.toUpperCase()} (%)`);
  elements.historyCaption.textContent = t("{label} · {count} mesure(s) sur 48 h", { label: sampleLabel, count: samples.length });
}

async function refreshHistory(force = false) {
  const key = elements.historyDevice.value;
  if (!key) {
    historyCache = { key: null, loadedAt: 0, value: null };
    drawHistory();
    return;
  }
  const hasHistory = Object.values(historyCache.value || {}).some(samples => samples.length);
  if (!force && historyCache.key === key && Date.now() - historyCache.loadedAt < 25_000 && (hasHistory || !monitoring.devices.some(device => device.system?.data || device.vpn?.data))) return;
  historyCache = { key, loadedAt: Date.now(), value: await requestJson(`/api/monitoring/history?key=${encodeURIComponent(key)}`) };
  drawHistory();
}

async function refreshMonitoring() {
  try {
    monitoring = await requestJson("/api/monitoring");
    monitoringError = "";
    renderMonitoringStatus();
    renderHistoryOptions();
    render();
    await refreshHistory();
  } catch (error) {
    monitoringError = error.message;
    renderMonitoringStatus();
  }
}

function renderMonitoringStatus() {
  if (monitoringError) {
    elements.monitoringStatus.textContent = t("Supervision indisponible · vérifier le service API");
    elements.monitoringStatus.dataset.state = "error";
    elements.alertList.replaceChildren();
    const item = document.createElement("li");
    item.className = "alert-empty";
    item.textContent = t(monitoringError);
    elements.alertList.append(item);
  } else if (monitoring.generatedAt) {
    const active = monitoring.alerts.filter((alert) => !alert.resolved).length;
    elements.monitoringStatus.textContent = t("{status} · Mis à jour {date}", {
      status: active ? t("{count} alerte(s)", { count: active }) : t("Aucune alerte"),
      date: formattedDate(monitoring.generatedAt),
    });
    elements.monitoringStatus.dataset.state = active ? "alert" : "ok";
    renderAlerts();
  }
}

function render() {
  const organizations = new Set(inventory.firewalls.map((item) => item.organizationId));
  const sites = new Set(inventory.firewalls.map((item) => `${item.organizationId}:${item.siteId}`));
  const query = elements.filterInput.value.trim().toLocaleLowerCase(NebulaI18n.language);
  const visibleFirewalls = inventory.firewalls.filter((firewall) =>
    [firewall.name, firewall.id, firewall.model, firewall.organizationName, firewall.siteName, firewall.serialNumber, firewall.macAddress]
      .some((value) => String(value || "").toLocaleLowerCase(NebulaI18n.language).includes(query)),
  );

  elements.firewallCount.textContent = String(inventory.firewalls.length);
  elements.organizationCount.textContent = String(organizations.size);
  elements.siteCount.textContent = String(sites.size);
  elements.scannedAt.textContent = formattedDate(inventory.scannedAt);
  elements.visibleCount.textContent = t(visibleFirewalls.length === 1 ? "{count} appareil" : "{count} appareils", { count: visibleFirewalls.length });
  elements.rows.replaceChildren();
  const deviceStatus = new Map(monitoring.devices.map((device) => [device.key, device]));

  for (const firewall of visibleFirewalls) {
    const status = deviceStatus.get(JSON.stringify([firewall.organizationId, firewall.siteId, firewall.id]));
    const row = document.createElement("tr");
    addDeviceCell(row, firewall);
    row.append(
      makeCell(firewall.model),
      makeCell(firewall.organizationName),
      makeCell(firewall.siteName),
    );
    addVpnCell(row, status?.vpn);
    addOnlineCell(row, status?.online);
    addWanCell(row, status?.ports, status?.interfaces);
    addMetricCell(row, status?.system?.data?.cpu ?? null, status?.system?.state, "%");
    addMetricCell(row, status?.system?.data?.ram ?? null, status?.system?.state, "%");
    addMetricCell(row, status?.system?.data?.sessions ?? null, status?.system?.state);
    addSerialCell(row, firewall);
    elements.rows.append(row);
  }

  const showEmpty = visibleFirewalls.length === 0;
  elements.emptyState.hidden = !showEmpty;
  if (showEmpty && query) {
    elements.emptyTitle.textContent = t("Aucun résultat");
    elements.emptyDetail.textContent = t("Aucun pare-feu ne correspond à ce filtre.");
  } else if (showEmpty && inventory.scannedAt) {
    elements.emptyTitle.textContent = t("Aucun pare-feu détecté");
    elements.emptyDetail.textContent = t("Aucun appareil de type firewall n'a été trouvé.");
  } else {
    elements.emptyTitle.textContent = t("Aucun inventaire enregistré");
    elements.emptyDetail.textContent = t("Le premier scan apparaîtra ici.");
  }
}

async function requestJson(url, options) {
  const response = await fetch(url, options);
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error("Le serveur a renvoyé une page HTML au lieu des données. Vérifiez le routage des requêtes /api/ vers le service backend.");
  }
  if (!response.ok) throw new Error(body.message || "Une erreur est survenue.");
  return body;
}

async function scan() {
  elements.scanButton.disabled = true;
  elements.scanButton.classList.add("is-scanning");
  showNotice("Scan complet en cours…");
  try {
    inventory = await requestJson("/api/scan", { method: "POST" });
    render();
    void refreshMonitoring();
    showNotice("");
  } catch (error) {
    showNotice(error.message);
  } finally {
    elements.scanButton.disabled = false;
    elements.scanButton.classList.remove("is-scanning");
  }
}

async function start() {
  for (const button of document.querySelectorAll("[data-language]")) {
    button.addEventListener("click", () => {
      NebulaI18n.setLanguage(button.dataset.language);
      render();
      renderMonitoringStatus();
      showNotice(noticeMessage);
      drawHistory();
    });
  }
  elements.scanButton.addEventListener("click", scan);
  elements.filterInput.addEventListener("input", render);
  elements.historyDevice.addEventListener("change", () => { void refreshHistory(true).catch(() => drawHistory()); });
  elements.historyKind.addEventListener("change", drawHistory);
  new ResizeObserver(drawHistory).observe(elements.historyChart);
  window.setInterval(() => { void refreshMonitoring(); }, 30_000);

  try {
    inventory = await requestJson("/api/inventory");
    render();
    void refreshMonitoring();
    if (!inventory.configured) {
      showNotice("Clé API absente. Créez .env à partir de .env.example et renseignez NEBULA_API_KEY.");
    } else if (!inventory.scannedAt) {
      await scan();
    }
  } catch (error) {
    showNotice(error.message);
  }
}

start();