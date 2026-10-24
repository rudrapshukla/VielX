/**
 * tests/popup.smoke.test.js — opens popup/popup.html in a simulated browser and
 * checks that all buttons, Studio Web App launcher, Safety Code verification,
 * and Master Vault Lock/Unlock work.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const { JSDOM } = require("./dom_harness.js");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function openPopup(tabUrl, initialStorage = {}) {
  const data = { ...initialStorage };
  const changeListeners = [];
  const sentToTab = [];
  const createdTabs = [];

  const chrome = {
    runtime: {
      id: "test-extension",
      getURL: (rel) => `chrome-extension://test-extension/${rel.replace(/^\//, "")}`,
    },
    tabs: {
      query: async () => [{ id: 7, url: tabUrl }],
      create: async (opts) => {
        createdTabs.push(opts);
        return { id: 99, ...opts };
      },
      sendMessage: async (id, message) => {
        sentToTab.push(message);
        return { ok: true };
      },
    },
    storage: {
      onChanged: { addListener: (fn) => changeListeners.push(fn) },
      local: {
        async get(keys) {
          if (keys === null) return JSON.parse(JSON.stringify(data));
          const out = {};
          for (const key of Array.isArray(keys) ? keys : [keys]) {
            if (key in data) out[key] = JSON.parse(JSON.stringify(data[key]));
          }
          return out;
        },
        async set(values) {
          Object.assign(data, JSON.parse(JSON.stringify(values)));
          changeListeners.forEach((fn) => fn({}, "local"));
        },
        async remove(key) {
          delete data[key];
          changeListeners.forEach((fn) => fn({}, "local"));
        },
      },
    },
  };

  const dom = await JSDOM.fromFile(path.join(__dirname, "..", "popup", "popup.html"), {
    runScripts: "dangerously",
    resources: "usable",
    pretendToBeVisual: true,
    beforeParse(window) {
      window.chrome = chrome;
      Object.defineProperty(window, "crypto", { value: webcrypto, configurable: true });
      window.TextEncoder = TextEncoder;
      window.TextDecoder = TextDecoder;
    },
  });

  await sleep(150);

  const $ = (id) => dom.window.document.getElementById(id);
  return { dom, data, sentToTab, createdTabs, $ };
}

test("no chat open: shows 'No conversation open' card, has no popup message box, and launches VeilX Studio Web App", async () => {
  const p = await openPopup("https://www.instagram.com/");
  assert.equal(p.$("noChatCard").hidden, false);
  assert.equal(p.$("chatCard").hidden, true);
  assert.equal(p.$("setupCard").hidden, true);
  assert.equal(p.$("composeInput"), null, "Send message box was removed from popup as requested");
  assert.match(p.$("statusText").textContent, /on/);

  p.$("openStudioBtn").click();
  await sleep(50);
  assert.equal(p.createdTabs.length, 1);
  assert.equal(p.createdTabs[0].url, "chrome-extension://test-extension/app/app.html");
});

test("chat without a key: shows setup; Generate fills a strong passphrase", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/");
  assert.equal(p.$("setupCard").hidden, false);
  assert.match(p.$("chatState").textContent, /No key yet/);
  assert.equal(p.$("chatId").textContent, "…567890");

  p.$("genBtn").click();
  assert.match(p.$("passInput").value, /^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$/);
});

test("a short passphrase is rejected and nothing is saved", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/");
  p.$("passInput").value = "short";
  p.$("savePassBtn").click();
  await sleep(100);
  assert.match(p.$("message").textContent, /at least 12/);
  assert.equal(p.data["conv:1234567890"], undefined);
});

test("saving a passphrase stores a key (never the passphrase) and shows Ready", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/");
  p.$("passInput").value = "my shared passphrase";
  p.$("savePassBtn").click();
  await sleep(1500);

  const record = p.data["conv:1234567890"];
  assert.equal(record.mode, "passphrase");
  assert.ok(record.keyB64);
  assert.ok(!JSON.stringify(p.data).includes("my shared passphrase"));
  assert.match(p.$("chatState").textContent, /Ready/);
  assert.equal(p.$("passInput").value, "");
  assert.equal(p.$("removeBtn").hidden, false);
});

test("Remove key needs two clicks", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/", {
    "conv:1234567890": { mode: "passphrase", keyB64: "AAAA", verified: true },
  });
  p.$("removeBtn").click();
  await sleep(50);
  assert.ok(p.data["conv:1234567890"], "first click only arms the button");
  assert.match(p.$("removeBtn").textContent, /again/);

  p.$("removeBtn").click();
  await sleep(100);
  assert.equal(p.data["conv:1234567890"], undefined);
  assert.equal(p.$("setupCard").hidden, false);
});

test("Key exchange tab: the button asks the page to send our key", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/");
  p.$("tabKex").click();
  assert.equal(p.$("panelKex").hidden, false);
  assert.equal(p.$("panelPass").hidden, true);

  p.$("startKexBtn").click();
  await sleep(100);
  assert.equal(p.sentToTab.length, 1);
  assert.equal(p.sentToTab[0].type, "GPV_SEND_KEY");
});

test("a finished ML-KEM-768 key exchange shows the safety code and Verify safety code button", async () => {
  const GPVCrypto = require("../src/crypto.js");
  const me = await GPVCrypto.generateIdentity();
  const them = await GPVCrypto.generateIdentity();
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/", {
    identity: me,
    "conv:1234567890": {
      mode: "ecdh",
      keyB64: "AAAA",
      peerPub: them.publicKey,
      sentMyKey: true,
      pqSharedB64: "BBBB",
      quantumSafe: true,
      verified: false,
    },
  });
  assert.equal(p.$("safetyBox").hidden, false);
  assert.equal(p.$("verifyBtn").hidden, false);

  p.$("verifyBtn").click();
  await sleep(150);
  assert.equal(p.data["conv:1234567890"].verified, true);
  assert.equal(p.$("verifyBtn").hidden, true);
});

test("Master Vault Lock encrypts keys in storage and Unlock restores them", async () => {
  const p = await openPopup("https://www.instagram.com/direct/t/1234567890/", {
    "conv:1234567890": { mode: "passphrase", keyB64: "SECRET_KEY_B64", verified: true },
  });
  assert.equal(p.$("vaultBadge").textContent, "Unlocked");

  p.$("vaultPassInput").value = "my-master-vault-passphrase-123";
  p.$("lockVaultBtn").click();
  await sleep(1800);

  assert.equal(p.data["conv:1234567890"], undefined, "Plaintext key wiped from storage");
  assert.ok(p.data.vaultEnvelope, "Encrypted vaultEnvelope stored");
  assert.equal(p.data.vaultLocked, true);
  assert.equal(p.$("vaultBadge").textContent, "Locked");

  p.$("vaultPassInput").value = "my-master-vault-passphrase-123";
  p.$("unlockVaultBtn").click();
  await sleep(1800);

  assert.equal(p.data.vaultLocked, false);
  assert.equal(p.data["conv:1234567890"].keyB64, "SECRET_KEY_B64", "Key restored after unlock");
  assert.equal(p.$("vaultBadge").textContent, "Unlocked");
});

test("master toggle and Purplish-Bluish UI toggle save settings", async () => {
  const p = await openPopup("https://www.instagram.com/");
  p.$("masterToggle").click();
  await sleep(100);
  assert.equal(p.data.enabled, false);
  assert.match(p.$("statusText").textContent, /off/);

  p.$("beautifyToggle").click();
  await sleep(100);
  assert.equal(p.data.beautifyUi, false);
});
