/**
 * src/store.js — persistent storage, locking and Key Vault (VeilX 1.0.0).
 *
 * Storage layout (all values are JSON in chrome.storage.local):
 *   settings            enabled, autoDecrypt, beautifyUi, padMessages, requireVerification, relayUrl, relaySecret
 *   conv:<threadId>     per-chat record (mode, convId, state, pending handshake, verified, …)
 *   snd:<convId>        sending chain   {sid, ckB64, n}              (written only by the composer)
 *   rcv:<convId>        receiving chains {chains:{[sid]:{ckB64,n,skipped}}}  (written only by the page script)
 *   inh:<convId>        decrypted-history of received messages       (page script)
 *   outh:<convId>       decrypted-history of sent messages           (composer)
 *
 * Keys that hold secrets or plaintext are listed in SECRET_PREFIXES and are the
 * ones the Key Vault seals when it is locked.
 */

globalThis.VX = globalThis.VX || {};

VX.store = (() => {
  "use strict";

  // Global Zero-Knowledge Cloudflare Worker Relay URL
  const DEFAULT_RELAY_URL = "https://veilx-relay.therealrudrashukla.workers.dev";

  const SECRET_PREFIXES = ["conv:", "snd:", "rcv:", "inh:", "outh:"];
  const isSecretKey = (k) => SECRET_PREFIXES.some((p) => k.startsWith(p));

  function convKey(threadId) {
    return "conv:" + threadId;
  }

  // ── Locking ──────────────────────────────────────────────────────────────

  const chains = new Map();
  async function withLock(name, fn) {
    if (typeof navigator !== "undefined" && navigator.locks && navigator.locks.request) {
      return navigator.locks.request("veilx:" + name, fn);
    }
    const prev = chains.get(name) || Promise.resolve();
    let release;
    const gate = new Promise((r) => (release = r));
    chains.set(name, prev.then(() => gate));
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (chains.get(name) === gate) chains.delete(name);
    }
  }

  // ── Vault guard ──────────────────────────────────────────────────────────

  async function getVaultStatus() {
    const saved = await chrome.storage.local.get(["vaultLocked", "vaultEnvelope"]);
    return {
      locked: Boolean(saved.vaultLocked && saved.vaultEnvelope),
      hasVault: Boolean(saved.vaultEnvelope),
    };
  }

  async function assertUnlocked() {
    const v = await getVaultStatus();
    if (v.locked) throw new Error("VeilX vault is locked. Unlock it from the VeilX toolbar icon.");
  }

  // ── Settings ─────────────────────────────────────────────────────────────

  async function getSettings() {
    const saved = await chrome.storage.local.get([
      "enabled",
      "autoDecrypt",
      "beautifyUi",
      "padMessages",
      "requireVerification",
      "relayUrl",
      "relaySecret",
    ]);
    const rawRelay = typeof saved.relayUrl === "string" ? saved.relayUrl.trim().replace(/\/+$/, "") : "";
    const cleanRelay =
      rawRelay && !rawRelay.includes("127.0.0.1") && !rawRelay.includes("localhost")
        ? rawRelay
        : DEFAULT_RELAY_URL;
    return {
      enabled: saved.enabled !== false,
      autoDecrypt: saved.autoDecrypt !== false,
      beautifyUi: saved.beautifyUi !== false,
      padMessages: saved.padMessages !== false,
      requireVerification: saved.requireVerification !== false,
      relayUrl: cleanRelay,
      relaySecret: typeof saved.relaySecret === "string" ? saved.relaySecret.trim() : "",
    };
  }

  async function setSetting(name, value) {
    await chrome.storage.local.set({ [name]: value });
  }

  // ── Generic secret state ─────────────────────────────────────────────────

  async function getState(key) {
    const saved = await chrome.storage.local.get(key);
    return saved[key] || null;
  }

  async function setState(key, value) {
    await assertUnlocked();
    await chrome.storage.local.set({ [key]: value });
  }

  async function removeState(key) {
    await scrubKeys([key]);
  }

  async function scrubKeys(keys) {
    for (const k of keys) {
      try {
        const junk = VX.crypto.bytesToBase64(VX.crypto.randomBytes(64));
        await chrome.storage.local.set({ [k]: junk });
      } catch (_) {}
      await chrome.storage.local.remove(k);
    }
  }

  // ── Per-chat records ─────────────────────────────────────────────────────

  async function getConversation(threadId) {
    if (!threadId) return null;
    return getState(convKey(threadId));
  }

  async function saveConversation(threadId, record) {
    if (!threadId) return;
    await setState(convKey(threadId), { ...record, updatedAt: Date.now() });
  }

  async function removeConversation(threadId) {
    if (!threadId) return;
    const rec = await getConversation(threadId);
    const keys = [convKey(threadId)];
    if (rec && rec.convId) {
      keys.push("snd:" + rec.convId, "rcv:" + rec.convId, "inh:" + rec.convId, "outh:" + rec.convId);
    }
    await scrubKeys(keys);
  }

  async function verifyConversation(threadId) {
    return withLock("conv:" + threadId, async () => {
      const rec = await getConversation(threadId);
      if (!rec || !rec.convId || rec.mode !== "pq") return null;
      const next = { ...rec, verified: true, verifiedAt: Date.now() };
      await saveConversation(threadId, next);
      return next;
    });
  }

  // ── Master Key Vault ─────────────────────────────────────────────────────

  async function lockVault(masterPassphrase) {
    if (!masterPassphrase || masterPassphrase.trim().length < 12) {
      throw new Error("Vault master passphrase must be at least 12 characters.");
    }
    const all = await chrome.storage.local.get(null);
    const secrets = {};
    for (const [k, v] of Object.entries(all)) if (isSecretKey(k)) secrets[k] = v;
    const envelope = await VX.crypto.sealVaultData(masterPassphrase, secrets);
    await chrome.storage.local.set({ vaultEnvelope: envelope, vaultLocked: true });
    await scrubKeys(Object.keys(secrets));
    return { ok: true, count: Object.keys(secrets).length };
  }

  async function unlockVault(masterPassphrase) {
    const saved = await chrome.storage.local.get("vaultEnvelope");
    if (!saved || !saved.vaultEnvelope) throw new Error("No locked vault found.");
    const secrets = await VX.crypto.unsealVaultData(masterPassphrase, saved.vaultEnvelope);
    for (const k of Object.keys(secrets)) if (!isSecretKey(k)) delete secrets[k];
    await chrome.storage.local.set({ ...secrets, vaultLocked: false });
    await chrome.storage.local.remove("vaultEnvelope");
    return { ok: true, count: Object.keys(secrets).length };
  }

  return {
    DEFAULT_RELAY_URL,
    convKey, withLock, getVaultStatus, assertUnlocked,
    getSettings, setSetting,
    getState, setState, removeState,
    getConversation, saveConversation, removeConversation, verifyConversation,
    lockVault, unlockVault,
  };
})();

if (typeof module !== "undefined") module.exports = VX.store;
