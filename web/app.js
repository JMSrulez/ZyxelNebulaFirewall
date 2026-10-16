const elements = {
  scanButton: document.querySelector("#scan-button"),
  notice: document.querySelector("#notice"),
  firewallCount: document.querySelector("#firewall-count"),
  organizationCount: document.querySelector("#organization-count"),
  siteCount: document.querySelector("#site-count"),
  scannedAt: document.querySelector("#scanned-at"),
  filterInput: document.querySelector("#filter-input"),
  rows: document.querySelector("#firewall-rows"),
  emptyState: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyDetail: document.querySelector("#empty-detail"),
  visibleCount: document.querySelector("#visible-count"),
};

let inventory = { firewalls: [], scannedAt: null };

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.hidden = !message;
}

function formattedDate(value) {
  if (!value) return "Jamais";
  return new Intl.DateTimeFormat("fr-FR", {
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
  name.textContent = firewall.name || firewall.model || "Pare-feu Zyxel";
  const id = document.createElement("span");
  id.className = "device-id";
  id.textContent = firewall.id || "Identifiant indisponible";
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

function render() {
  const organizations = new Set(inventory.firewalls.map((item) => item.organizationId));
  const sites = new Set(inventory.firewalls.map((item) => `${item.organizationId}:${item.siteId}`));
  const query = elements.filterInput.value.trim().toLocaleLowerCase("fr");
  const visibleFirewalls = inventory.firewalls.filter((firewall) =>
    [firewall.name, firewall.id, firewall.model, firewall.organizationName, firewall.siteName, firewall.serialNumber, firewall.macAddress]
      .some((value) => String(value || "").toLocaleLowerCase("fr").includes(query)),
  );

  elements.firewallCount.textContent = String(inventory.firewalls.length);
  elements.organizationCount.textContent = String(organizations.size);
  elements.siteCount.textContent = String(sites.size);
  elements.scannedAt.textContent = formattedDate(inventory.scannedAt);
  elements.visibleCount.textContent = `${visibleFirewalls.length} ${visibleFirewalls.length === 1 ? "appareil" : "appareils"}`;
  elements.rows.replaceChildren();

  for (const firewall of visibleFirewalls) {
    const row = document.createElement("tr");
    addDeviceCell(row, firewall);
    row.append(
      makeCell(firewall.model),
      makeCell(firewall.organizationName),
      makeCell(firewall.siteName),
    );
    addSerialCell(row, firewall);
    elements.rows.append(row);
  }

  const showEmpty = visibleFirewalls.length === 0;
  elements.emptyState.hidden = !showEmpty;
  if (showEmpty && query) {
    elements.emptyTitle.textContent = "Aucun résultat";
    elements.emptyDetail.textContent = "Aucun pare-feu ne correspond à ce filtre.";
  } else if (showEmpty && inventory.scannedAt) {
    elements.emptyTitle.textContent = "Aucun pare-feu détecté";
    elements.emptyDetail.textContent = "Aucun appareil de type firewall n'a été trouvé.";
  } else {
    elements.emptyTitle.textContent = "Aucun inventaire enregistré";
    elements.emptyDetail.textContent = "Le premier scan apparaîtra ici.";
  }
}

async function requestJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.json();
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
    showNotice("");
  } catch (error) {
    showNotice(error.message);
  } finally {
    elements.scanButton.disabled = false;
    elements.scanButton.classList.remove("is-scanning");
  }
}

async function start() {
  elements.scanButton.addEventListener("click", scan);
  elements.filterInput.addEventListener("input", render);

  try {
    inventory = await requestJson("/api/inventory");
    render();
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