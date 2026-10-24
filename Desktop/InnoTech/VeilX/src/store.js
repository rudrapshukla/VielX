/**
 * src/store.js — Persistent Storage, Key History, Ratchet & Master Key Vault (VeilX v5.2.0).
 */

globalThis.GPV = globalThis.GPV || {};

GPV.store = (() => {
  "use strict";

  const MAX_OWN_TOKENS = 300;

  function convKey(threadId) {
    return "conv:" + threadId;
  }

  // ── Settings ─────────────────────────────────────────────────────────────

  async function getSettings() {
    const saved = await chrome.storage.local.get([
      "enabled",
      "autoDecrypt",
      "beautifyUi",
      "padMessages",
      "requireVerification",
    ]);
    return {
      enabled: saved.enabled !== false,
      autoDecrypt: saved.autoDecrypt !== false,
      beautifyUi: saved.beautifyUi !== false,
      padMessages: saved.padMessages !== false,
      requireVerification: saved.requireVerification === true, // Opt-in strict gate in popup so normal chatting is effortless
    };
  }

  async function setSetting(name, value) {
    await chrome.storage.local.set({ [name]: value });
  }

  // ── Per-chat records ─────────────────────────────────────────────────────

  async function getConversation(threadId) {
    if (!threadId) return null;
    const key = convKey(threadId);
    const saved = await chrome.storage.local.get(key);
    return saved[key] || null;
  }

  async function saveConversation(threadId, record) {
    if (!threadId) return;
    await chrome.storage.local.set({
      [convKey(threadId)]: { ...record, updatedAt: Date.now() },
    });
  }

  async function removeConversation(threadId) {
    if (!threadId) return;
    await chrome.storage.local.remove(convKey(threadId));
  }

  async function verifyConversation(threadId) {
    const record = await getConversation(threadId);
    if (!record) return null;
    const updated = { ...record, verified: true, verifiedAt: Date.now() };
    await saveConversation(threadId, updated);
    return updated;
  }

  /**
   * Allocate the next monotonic outbound sequence number and record `token`
   * if provided.
   */
  async function allocateNextSeq(threadId) {
    const record = await getConversation(threadId);
    if (!record) return 1;
    const nextSeq = (Number.isInteger(record.nextSeq) ? record.nextSeq : 0) + 1;
    await saveConversation(threadId, { ...record, nextSeq });
    return nextSeq;
  }

  /**
   * Record a message ID / IV token that WE just encrypted and sent so that
   * when our own sent message appears in Instagram's DOM, we recognize it as
   * ours and never flag it as a replay.
   */
  async function recordOwnSentToken(threadId, token) {
    if (!threadId || !token) return;
    const record = await getConversation(threadId);
    if (!record) return;
    const ownTokens = Array.isArray(record.ownTokens)
      ? record.ownTokens.slice()
      : [];
    if (!ownTokens.includes(token)) {
      ownTokens.push(token);
      if (ownTokens.length > MAX_OWN_TOKENS) {
        ownTokens.splice(0, ownTokens.length - MAX_OWN_TOKENS);
      }
      await saveConversation(threadId, { ...record, ownTokens });
    }
  }

  /**
   * Destructive Forward-Secrecy Chain Ratchet step in storage:
   * Advances `record.chainKeyB64` by one HMAC-SHA256 step, overwrites the old
   * chain key in storage with `nextChainKeyB64`, and returns `{ messageAesKey, seq }`.
   */
  async function advanceConversationRatchet(threadId) {
    const record = await getConversation(threadId);
    if (!record || (!record.chainKeyB64 && !record.keyB64)) {
      throw new Error("No conversation key available to ratchet");
    }
    const currentChainB64 = record.chainKeyB64 || record.keyB64;
    const seq = (Number.isInteger(record.ratchetSeq) ? record.ratchetSeq : 0) + 1;
    const step = await GPV.crypto.ratchetChainStep(currentChainB64, seq, threadId);

    // Overwrite chainKeyB64 in storage so the previous chain key is permanently destroyed!
    await saveConversation(threadId, {
      ...record,
      chainKeyB64: step.nextChainKeyB64,
      ratchetSeq: seq,
    });
    return {
      messageAesKey: step.messageAesKey,
      messageKeyB64: step.messageKeyB64,
      nextChainKeyB64: step.nextChainKeyB64,
      seq,
    };
  }

  // ── This device's key pair (NIST FIPS 203 ML-KEM-768 + ECDH P-256) ───────

  async function getIdentity() {
    const saved = await chrome.storage.local.get("identity");
    return saved.identity || null;
  }

  async function getOrCreateIdentity() {
    const existing = await getIdentity();
    if (
      existing &&
      existing.quantumSafe &&
      existing.privateJwk &&
      existing.privateJwk.mlkemDkB64
    ) {
      return existing;
    }

    const created = await GPV.crypto.generateIdentity();

    const again = await getIdentity();
    if (
      again &&
      again.quantumSafe &&
      again.privateJwk &&
      again.privateJwk.mlkemDkB64
    ) {
      return again;
    }

    const pastSaved = await chrome.storage.local.get("ownPastKeys");
    const ownPastKeys = Array.isArray(pastSaved.ownPastKeys)
      ? pastSaved.ownPastKeys.slice()
      : [];
    if (existing && existing.publicKey && !ownPastKeys.includes(existing.publicKey)) {
      ownPastKeys.push(existing.publicKey);
    }
    if (!ownPastKeys.includes(created.publicKey)) {
      ownPastKeys.push(created.publicKey);
    }

    await chrome.storage.local.set({ identity: created, ownPastKeys });
    return created;
  }

  async function isOwnPublicKey(pubB64) {
    if (!pubB64) return false;
    const saved = await chrome.storage.local.get(["identity", "ownPastKeys"]);
    const id = saved.identity;
    if (id && (id.publicKey === pubB64 || id.classicalPublicKey === pubB64)) {
      return true;
    }
    if (Array.isArray(saved.ownPastKeys) && saved.ownPastKeys.includes(pubB64)) {
      return true;
    }
    return false;
  }

  // ── Active Master Vault Encryption at Rest ───────────────────────────────

  async function getVaultStatus() {
    const saved = await chrome.storage.local.get(["vaultLocked", "vaultEnvelope"]);
    return {
      locked: Boolean(saved.vaultLocked && saved.vaultEnvelope),
      hasVault: Boolean(saved.vaultEnvelope),
    };
  }

  async function lockVault(masterPassphrase) {
    if (!masterPassphrase || masterPassphrase.trim().length < 12) {
      throw new Error("Vault master passphrase must be at least 12 characters.");
    }
    const all = await chrome.storage.local.get(null);
    const secrets = {};
    const keysToRemove = [];
    for (const [k, v] of Object.entries(all)) {
      if (k === "identity" || k === "ownPastKeys" || k.startsWith("conv:")) {
        secrets[k] = v;
        keysToRemove.push(k);
      }
    }
    const envelope = await GPV.crypto.sealVaultData(masterPassphrase, secrets);
    await chrome.storage.local.set({ vaultEnvelope: envelope, vaultLocked: true });
    for (const k of keysToRemove) {
      await chrome.storage.local.remove(k);
    }
    return { ok: true, count: keysToRemove.length };
  }

  async function unlockVault(masterPassphrase) {
    const saved = await chrome.storage.local.get("vaultEnvelope");
    if (!saved || !saved.vaultEnvelope) {
      throw new Error("No locked vault found.");
    }
    const secrets = await GPV.crypto.unsealVaultData(masterPassphrase, saved.vaultEnvelope);
    await chrome.storage.local.set({ ...secrets, vaultLocked: false });
    await chrome.storage.local.remove("vaultEnvelope");
    return { ok: true, count: Object.keys(secrets).length };
  }

  return {
    convKey,
    getSettings,
    setSetting,
    getConversation,
    saveConversation,
    removeConversation,
    verifyConversation,
    allocateNextSeq,
    recordOwnSentToken,
    advanceConversationRatchet,
    getIdentity,
    getOrCreateIdentity,
    isOwnPublicKey,
    getVaultStatus,
    lockVault,
    unlockVault,
  };
})();

if (typeof module !== "undefined") module.exports = GPV.store;
