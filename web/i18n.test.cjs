const test = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { runInNewContext } = require("node:vm");

const source = readFileSync(`${__dirname}/i18n.js`, "utf8");

function load(language, saved, blocked = false) {
  const storage = new Map(saved ? [["nebula-language", saved]] : []);
  const document = {
    documentElement: {},
    createTreeWalker: () => ({ nextNode: () => false }),
    querySelectorAll: () => [],
  };
  const context = {
    document,
    navigator: { language },
    NodeFilter: { SHOW_TEXT: 4 },
    localStorage: {
      getItem: key => { if (blocked) throw new Error("blocked"); return storage.get(key); },
      setItem: (key, value) => { if (blocked) throw new Error("blocked"); storage.set(key, value); },
    },
  };
  runInNewContext(source, context);
  return { api: context.NebulaI18n, document, storage };
}

test("French browser variants select French; other languages default to English", () => {
  for (const language of ["fr", "fr-FR", "fr-CA"]) assert.equal(load(language).api.language, "fr");
  for (const language of ["en-US", "de-DE", "es", "", undefined]) assert.equal(load(language).api.language, "en");
});

test("manual choice overrides browser locale, persists and updates document language", () => {
  const { api, storage, document } = load("fr-FR");
  api.setLanguage("en");
  assert.equal(document.documentElement.lang, "en");
  assert.equal(storage.get("nebula-language"), "en");
  assert.equal(load("fr-FR", "en").api.language, "en");
  assert.equal(load("en-GB", "fr").api.language, "fr");
  assert.equal(load("de-DE", "invalid").api.language, "en");
  api.setLanguage("invalid");
  assert.equal(api.language, "en");
});

test("blocked storage does not prevent detection or switching", () => {
  const { api } = load("fr-FR", null, true);
  assert.equal(api.language, "fr");
  api.setLanguage("en");
  assert.equal(api.t("En ligne"), "Online");
});

test("dynamic labels, stored alerts and error codes are translated without changing device names", () => {
  const { api } = load("en-US");
  assert.equal(api.t("{count} appareils", { count: 3 }), "3 devices");
  assert.equal(api.t("Collecte système impossible (HTTP_403)."), "system collection failed (HTTP_403).");
  assert.equal(api.t("Pare-feu hors ligne de Nebula sur deux mesures."), "Firewall offline in Nebula on two consecutive measurements.");
  assert.equal(api.t("CPU ≥ 90 % sur deux mesures."), "CPU ≥ 90% on two consecutive measurements.");
  assert.equal(api.t("FW01-DC"), "FW01-DC");
  api.setLanguage("fr");
  assert.equal(api.t("En ligne"), "En ligne");
});