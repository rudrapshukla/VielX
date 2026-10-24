/**
 * src/content.js — VeilX v5.2.0 Content Script Conductor.
 *
 * VeilX v5.2.0 · NIST FIPS 203 ML-KEM-768 + ECDH P-256 · Created by Team Monolith
 * Source: https://github.com/rudrapshukla/guptavarta   License: MIT
 */

(function () {
  "use strict";

  const gpvCrypto = GPV.crypto;
  const { store, dom, ui, util } = GPV;

  const MSG_PREFIX = gpvCrypto.MSG_PREFIX; // "GPV2:"
  const KEY_PREFIX = gpvCrypto.KEY_PREFIX; // "GPV2K:"
  const MAX_DECRYPTS_PER_SCAN = 40;

  let settings = {
    enabled: true,
    autoDecrypt: true,
    beautifyUi: true,
    padMessages: true,
    requireVerification: false,
  };

  let sending = false;
  const keyCache = new Map();
  const pendingBubbles = new Set();
  const warnedKeyChanges = new Set();

  // Map token -> DOM element currently displaying that token.
  const activeTokenElements = new Map(); // token -> { el, scanId }
  let currentScanPassId = 0;

  let activeComposer = null;
  let activeAnchorInput = null;
  let lastThreadId = null;

  // ── Keys & Smart Replay-Protected Decryption ─────────────────────────────

  async function buildCandidateKeys(record) {
    const keys = [];
    const seenB64 = new Set();

    async function addKeyB64(b64) {
      if (!b64 || seenB64.has(b64)) return;
      seenB64.add(b64);
      try {
        const rawBytes = gpvCrypto.base64ToBytes(b64);
        if (rawBytes.length === 32) {
          const aesKey = await gpvCrypto.importAesKey(rawBytes);
          keys.push({ aesKey, rawBytes, keyB64: b64 });
        }
      } catch (_) {}
    }

    if (record && record.keyB64) {
      await addKeyB64(record.keyB64);
    }
    if (record && Array.isArray(record.altKeysB64)) {
      for (const altB64 of record.altKeysB64) {
        await addKeyB64(altB64);
      }
    }

    if (record && record.mode === "ecdh" && record.peerPub) {
      try {
        const identity = await store.getIdentity();
        if (identity && identity.privateJwk && identity.publicKey) {
          const pqSecrets = [
            record.decapsulatedPqB64,
            record.myPqSecretB64,
            record.pqSharedB64,
          ].filter(Boolean);
          for (const pqB64 of pqSecrets) {
            try {
              const derivedBytes = await gpvCrypto.deriveSharedKey(
                identity.privateJwk,
                identity.publicKey,
                record.peerPub,
                gpvCrypto.base64ToBytes(pqB64)
              );
              await addKeyB64(gpvCrypto.bytesToBase64(derivedBytes));
            } catch (_) {}
          }
        }
      } catch (_) {}
    }

    return keys;
  }

  async function getKeyInfo(threadId) {
    if (!threadId) return null;
    if (keyCache.has(threadId)) return keyCache.get(threadId);

    const record = await store.getConversation(threadId);
    let info = null;
    if (record) {
      const candidateKeys = await buildCandidateKeys(record);
      if (candidateKeys.length > 0) {
        info = {
          key: candidateKeys[0].aesKey,
          rawBytes: candidateKeys[0].rawBytes,
          candidateKeys: candidateKeys.map((c) => c.aesKey),
          mode: record.mode,
          verified: record.mode === "passphrase" ? true : Boolean(record.verified),
          quantumSafe:
            record.mode === "ecdh" ? record.quantumSafe !== false : true,
          ownTokens: Array.isArray(record.ownTokens) ? record.ownTokens : [],
        };
      }
    }
    keyCache.set(threadId, info);
    return info;
  }

  async function tryDecryptWithKey(aesKey, blob, threadId) {
    try {
      return await gpvCrypto.decryptMessage(aesKey, blob, {
        returnEnvelope: true,
      });
    } catch (_) {
      if (threadId) {
        return await gpvCrypto.decryptMessage(aesKey, blob, {
          aad: threadId,
          returnEnvelope: true,
        });
      }
      throw _;
    }
  }

  /**
   * Check whether two DOM elements (`existingEl` and `el`) are distinct sibling
   * message bubbles inside the same conversation message list (as opposed to
   * a wrapper/child pair, a sidebar preview vs. chat bubble, or a re-render).
   */
  function areDistinctSiblingMessageBubbles(existingEl, el) {
    if (!existingEl || !el || existingEl === el) return false;
    if (!existingEl.isConnected || !el.isConnected) return false;
    if (existingEl.contains(el) || el.contains(existingEl)) return false;

    const p1 = existingEl.parentElement || existingEl.parentNode;
    const p2 = el.parentElement || el.parentNode;
    if (!p1 || !p2 || p1 === p2) return false;

    const gp1 = p1.parentElement || p1.parentNode;
    const gp2 = p2.parentElement || p2.parentNode;
    if (!gp1 || !gp2 || gp1 !== gp2) return false;

    return true;
  }

  async function decryptForThread(threadId, blob, el = null) {
    const vault = await store.getVaultStatus();
    if (vault.locked) return { ok: false, reason: "vault-locked" };

    let info = await getKeyInfo(threadId);
    if (!info || !info.key) return { ok: false, reason: "no-key" };

    let decoded = null;
    const keysToTry = info.candidateKeys || [info.key];

    for (const candidateKey of keysToTry) {
      try {
        decoded = await tryDecryptWithKey(candidateKey, blob, threadId);
        if (decoded) break;
      } catch (_) {}
    }

    if (!decoded) {
      try {
        keyCache.delete(threadId);
        await completeExchangeIfReady(threadId);
        info = await getKeyInfo(threadId);
        if (info && info.candidateKeys) {
          for (const candidateKey of info.candidateKeys) {
            try {
              decoded = await tryDecryptWithKey(candidateKey, blob, threadId);
              if (decoded) break;
            } catch (_) {}
          }
        }
      } catch (_) {}
    }

    if (!decoded) {
      try {
        const allStorage = await chrome.storage.local.get(null);
        for (const [k, otherRec] of Object.entries(allStorage)) {
          if (!k.startsWith("conv:") || k === "conv:" + threadId) continue;
          const otherThreadId = k.slice(5);
          const otherCandidates = await buildCandidateKeys(otherRec);
          for (const cand of otherCandidates) {
            try {
              decoded = await tryDecryptWithKey(cand.aesKey, blob, otherThreadId);
              if (decoded) break;
            } catch (_) {}
          }
          if (decoded) break;
        }
      } catch (_) {}
    }

    if (!decoded) {
      return { ok: false, reason: "bad" };
    }

    const token =
      (decoded.envelope && decoded.envelope.id) || decoded.ivB64;

    if (el && token) {
      const isOwnSent = Boolean(
        info && Array.isArray(info.ownTokens) && info.ownTokens.includes(token)
      );
      const keyId = `${threadId || "global"}:${token}`;
      const existingEntry = activeTokenElements.get(keyId);
      const existingEl = existingEntry ? existingEntry.el : null;
      const sameScanPass = Boolean(
        existingEntry && existingEntry.scanId === currentScanPassId
      );
      if (
        !isOwnSent &&
        !sameScanPass &&
        areDistinctSiblingMessageBubbles(existingEl, el)
      ) {
        return { ok: false, reason: "replay" };
      }
      activeTokenElements.set(keyId, { el, scanId: currentScanPassId });
    }

    let chunkLabel = null;
    if (
      decoded.envelope &&
      decoded.envelope.ct &&
      decoded.envelope.ct > 1
    ) {
      chunkLabel = `${decoded.envelope.ci}/${decoded.envelope.ct}`;
    }

    return {
      ok: true,
      text: decoded.text,
      quantumSafe: info ? info.quantumSafe : true,
      chunkLabel,
      seq: decoded.envelope ? decoded.envelope.seq : null,
    };
  }

  // ── Explaining Missing or Unverified Keys ────────────────────────────────

  async function showMissingOrUnverifiedToast(threadId) {
    const vault = await store.getVaultStatus();
    if (vault.locked) {
      ui.showToast(
        "Your VeilX Vault is locked. Unlock it in the VeilX popup before sending.",
        { kind: "warning" }
      );
      return;
    }

    const record = threadId ? await store.getConversation(threadId) : null;
    if (record && record.mode === "ecdh") {
      if (record.keyB64 && settings.requireVerification && !record.verified) {
        const identity = await store.getIdentity();
        const code =
          identity && record.peerPub
            ? await gpvCrypto.safetyCode(identity.publicKey, record.peerPub)
            : "";
        ui.showToast(
          `Verify safety code (${code}) with your contact before sending.`,
          {
            kind: "warning",
            actionLabel: "Verify Code",
            timeoutMs: 0,
            onAction: async () => {
              await store.verifyConversation(threadId);
              keyCache.delete(threadId);
              await syncComposerState();
              ui.showToast("Safety code verified! You can now send messages.", {
                kind: "info",
              });
            },
          }
        );
        return;
      }
      if (record.sentMyKey && !record.peerPub) {
        ui.showToast(
          "Your key exchange is not finished yet: waiting for your contact to send their key.",
          { kind: "warning" }
        );
        return;
      }
      if (record.peerPub && (!record.sentMyKey || !record.pqSharedB64)) {
        ui.showToast(
          "Your key exchange is not finished yet: send your key to complete the ML-KEM-768 handshake.",
          {
            kind: "warning",
            actionLabel: "Send my key",
            onAction: () => sendMyKey(),
          }
        );
        return;
      }
    }
    ui.showToast(
      "No key is set for this chat. Set a passphrase in the popup or click Send my key.",
      {
        kind: "warning",
        actionLabel: "Send my key",
        onAction: () => sendMyKey(),
      }
    );
  }

  // ── Sending Logic ────────────────────────────────────────────────────────

  function submitMessage(input) {
    if (!dom.clickSendButton()) dom.pressEnter(input);
  }

  async function encryptAndSendPlaintext(plaintext, fromNative = false, chunkMeta = null) {
    if (sending) return false;
    const trimmed = (plaintext || "").trim();
    if (!trimmed) return false;

    const input = dom.findMessageInput();
    if (!input) {
      ui.showToast("Open a chat first.", { kind: "error" });
      return false;
    }

    sending = true;
    try {
      if (!settings.enabled) {
        if (!fromNative) {
          const ready = await dom.writeInputText(input, trimmed);
          if (!ready) return false;
        }
        submitMessage(input);
        return true;
      }

      const threadId = dom.getThreadId();
      const info = await getKeyInfo(threadId);
      if (
        !info ||
        !info.key ||
        (info.mode === "ecdh" && settings.requireVerification && !info.verified)
      ) {
        await showMissingOrUnverifiedToast(threadId);
        return false;
      }

      const seq = await store.allocateNextSeq(threadId);
      const msgId = gpvCrypto.bytesToBase64(
        crypto.getRandomValues(new Uint8Array(8))
      );
      await store.recordOwnSentToken(threadId, msgId);

      const blob = await gpvCrypto.encryptMessage(info.key, trimmed, {
        pad: settings.padMessages,
        envelope: {
          seq,
          ts: Date.now(),
          id: msgId,
          gid: chunkMeta ? chunkMeta.gid : undefined,
          ci: chunkMeta ? chunkMeta.ci : undefined,
          ct: chunkMeta ? chunkMeta.ct : undefined,
        },
      });

      if (blob.length > util.MAX_MESSAGE_CHARS) {
        ui.showToast(
          "Message is too long once encrypted. Please shorten or split it.",
          { kind: "error" }
        );
        return false;
      }

      const ready = await dom.writeInputText(input, blob);
      if (!ready || dom.readInputText(input) !== blob) {
        await dom.writeInputText(input, fromNative ? trimmed : "");
        ui.showToast(
          "Could not safely place encrypted text in the box. Nothing was sent.",
          { kind: "error" }
        );
        return false;
      }
      submitMessage(input);
      return true;
    } finally {
      sending = false;
    }
  }

  async function sendCiphertext(blob, requestedThreadId) {
    if (
      typeof blob !== "string" ||
      !blob.startsWith(MSG_PREFIX) ||
      blob.length > util.MAX_MESSAGE_CHARS
    ) {
      throw new Error("Invalid encrypted message.");
    }
    try {
      if (gpvCrypto.base64ToBytes(blob.slice(MSG_PREFIX.length)).length < 28) {
        throw new Error();
      }
    } catch (err) {
      throw new Error("Invalid encrypted message.");
    }
    if (
      typeof requestedThreadId === "string" &&
      requestedThreadId &&
      dom.getThreadId() &&
      requestedThreadId !== dom.getThreadId()
    ) {
      throw new Error("The open chat changed. Try again.");
    }
    const input = dom.findMessageInput();
    if (!input) throw new Error("Open a chat first.");
    if (dom.readInputText(input)) {
      throw new Error("Clear Instagram's message box before sending securely.");
    }
    sending = true;
    try {
      const ready = await dom.writeInputText(input, blob);
      if (!ready || dom.readInputText(input) !== blob) {
        await dom.writeInputText(input, "");
        throw new Error(
          "Could not safely prepare the encrypted message. Nothing was sent."
        );
      }
      // Submit ONCE and wait 150ms (never double-fire pressEnter after clickSendButton,
      // which previously created a stuck second optimistic send in Instagram's queue!).
      submitMessage(input);
      await dom.wait(150);
      if (dom.readInputText(input).startsWith(MSG_PREFIX)) {
        throw new Error(
          "Instagram did not send the ciphertext. It remains in the message box."
        );
      }
      return { ok: true };
    } finally {
      sending = false;
    }
  }

  async function sendRawPackets(packets) {
    const input = dom.findMessageInput();
    if (!input) throw new Error("Open a chat first.");
    if (dom.readInputText(input)) {
      throw new Error("The message box is not empty. Clear it and try again.");
    }

    sending = true;
    try {
      for (let i = 0; i < packets.length; i++) {
        const ready = await dom.writeInputText(input, packets[i]);
        if (!ready) throw new Error("Could not write into the message box.");
        submitMessage(input);
        if (i < packets.length - 1) await dom.wait(180);
      }
    } finally {
      sending = false;
    }
  }

  // ── Defense-in-Depth Interception on Native Box ──────────────────────────

  function attachNativeInterceptors() {
    document.addEventListener(
      "keydown",
      (e) => {
        if (e._veilxSynthetic) return;
        if (!dom.isDmPage()) return;
        if (e.key !== "Enter" || e.shiftKey) return;
        if (e.isComposing || e.keyCode === 229) return;

        const input = dom.findMessageInput();
        if (!input) return;
        if (e.target !== input && !input.contains(e.target)) return;

        if (!settings.enabled) return;

        e.preventDefault();
        e.stopImmediatePropagation();

        if (sending) return;
        const text = dom.readInputText(input);
        if (!text || text.startsWith(MSG_PREFIX) || text.startsWith(KEY_PREFIX)) {
          return;
        }
        encryptAndSendPlaintext(text, true).catch((err) =>
          console.error("[VeilX] send error:", err)
        );
      },
      true
    );

    document.addEventListener(
      "click",
      (e) => {
        if (!dom.isDmPage()) return;
        if (!settings.enabled) return;

        const sendBtn = dom.closestSendButton(e.target);
        if (!sendBtn) return;

        const input = dom.findMessageInput();
        if (!input) return;

        const text = dom.readInputText(input);
        if (!text || text.startsWith(MSG_PREFIX) || text.startsWith(KEY_PREFIX)) {
          return;
        }

        e.preventDefault();
        e.stopImmediatePropagation();

        if (sending) return;
        encryptAndSendPlaintext(text, true).catch((err) =>
          console.error("[VeilX] send click error:", err)
        );
      },
      true
    );
  }

  // ── Standardized NIST FIPS 203 ML-KEM-768 + ECDH P-256 Handshake ─────────

  function getOrderedPqSecrets(myPublicB64, peerPublicB64, record) {
    const myPq = record ? record.myPqSecretB64 || null : null;
    const peerPq = record ? record.decapsulatedPqB64 || null : null;
    const legacyPq = record ? record.pqSharedB64 || null : null;

    const ordered = [];
    const add = (s) => {
      if (s && !ordered.includes(s)) ordered.push(s);
    };

    if (myPq && peerPq) {
      if (myPublicB64 <= peerPublicB64) {
        add(myPq);
        add(peerPq);
      } else {
        add(peerPq);
        add(myPq);
      }
    } else {
      add(peerPq);
      add(myPq);
    }
    add(legacyPq);
    return ordered;
  }

  async function completeExchangeIfReady(threadId) {
    const record = await store.getConversation(threadId);
    if (
      !record ||
      record.mode !== "ecdh" ||
      !record.peerPub ||
      !record.sentMyKey
    ) {
      return;
    }

    const identity = await store.getIdentity();
    if (!identity) return;

    const myBundle = gpvCrypto.parsePublicKeyBundle(identity.publicKey);
    const peerBundle = gpvCrypto.parsePublicKeyBundle(record.peerPub);
    const bothQuantumSafe = Boolean(myBundle.quantumSafe && peerBundle.quantumSafe);

    const orderedPqSecrets = getOrderedPqSecrets(
      identity.publicKey,
      record.peerPub,
      record
    );

    if (bothQuantumSafe && orderedPqSecrets.length === 0) {
      return;
    }

    const derivedKeysB64 = [];
    if (bothQuantumSafe) {
      for (const pqB64 of orderedPqSecrets) {
        const pqBytes = gpvCrypto.base64ToBytes(pqB64);
        const kBytes = await gpvCrypto.deriveSharedKey(
          identity.privateJwk,
          identity.publicKey,
          record.peerPub,
          pqBytes
        );
        const kB64 = gpvCrypto.bytesToBase64(kBytes);
        if (!derivedKeysB64.includes(kB64)) derivedKeysB64.push(kB64);
      }
    } else {
      const kBytes = await gpvCrypto.deriveSharedKey(
        identity.privateJwk,
        identity.publicKey,
        record.peerPub,
        null
      );
      derivedKeysB64.push(gpvCrypto.bytesToBase64(kBytes));
    }

    if (record.keyB64 && !derivedKeysB64.includes(record.keyB64)) {
      derivedKeysB64.push(record.keyB64);
    }
    if (Array.isArray(record.altKeysB64)) {
      for (const oldAlt of record.altKeysB64) {
        if (oldAlt && !derivedKeysB64.includes(oldAlt)) {
          derivedKeysB64.push(oldAlt);
        }
      }
    }

    const primaryKeyB64 = derivedKeysB64[0];
    const altKeysB64 = derivedKeysB64.slice(1);
    const primaryPqB64 = orderedPqSecrets[0] || record.pqSharedB64 || null;

    const alreadyUpToDate =
      record.keyB64 === primaryKeyB64 &&
      record.pqSharedB64 === primaryPqB64 &&
      JSON.stringify(record.altKeysB64 || []) === JSON.stringify(altKeysB64);

    if (alreadyUpToDate) {
      return;
    }

    const hadKeyBefore = Boolean(record.keyB64);
    const code = await gpvCrypto.safetyCode(identity.publicKey, record.peerPub);

    await store.saveConversation(threadId, {
      ...record,
      keyB64: primaryKeyB64,
      altKeysB64,
      pqSharedB64: primaryPqB64,
      chainKeyB64: primaryKeyB64,
      quantumSafe: bothQuantumSafe,
      verified: Boolean(record.verified),
    });
    keyCache.delete(threadId);
    retryPending();

    if (!hadKeyBefore) {
      if (settings.requireVerification && !record.verified) {
        ui.showToast(
          `ML-KEM-768 key ready! Safety code: ${code}. Click Verify Code after confirming with your contact.`,
          {
            kind: "info",
            actionLabel: "Verify Code",
            timeoutMs: 0,
            onAction: async () => {
              await store.verifyConversation(threadId);
              keyCache.delete(threadId);
              await syncComposerState();
              ui.showToast("Safety code verified! Conversation unlocked.", {
                kind: "info",
              });
            },
          }
        );
      } else {
        ui.showToast(
          bothQuantumSafe
            ? `NIST FIPS 203 ML-KEM-768 + P-256 key established! Safety code: ${code}`
            : `ECDH key established! Safety code: ${code}`,
          { kind: "info", timeoutMs: 9000 }
        );
      }
    }
    await syncComposerState();
  }

  async function sendMyKey() {
    const threadId = dom.getThreadId();
    if (!threadId) return { ok: false, error: "Open a chat first." };

    const existing = await store.getConversation(threadId);
    if (existing && existing.mode === "passphrase" && existing.keyB64) {
      return {
        ok: false,
        error: "This chat already uses a passphrase. Remove it first.",
      };
    }

    const identity = await store.getOrCreateIdentity();
    let kemCiphertextB64 = null;
    let myPqSecretB64 = existing ? existing.myPqSecretB64 || null : null;
    let myKemPeerPub = existing ? existing.myKemPeerPub || null : null;
    const decapsulatedPqB64 = existing ? existing.decapsulatedPqB64 || null : null;

    if (existing && existing.peerPub) {
      const peerBundle = gpvCrypto.parsePublicKeyBundle(existing.peerPub);
      if (peerBundle.quantumSafe) {
        if (
          myKemPeerPub === existing.peerPub &&
          existing.myKemCtB64 &&
          myPqSecretB64
        ) {
          kemCiphertextB64 = existing.myKemCtB64;
        } else if (!decapsulatedPqB64) {
          const encapsulated = await gpvCrypto.pqEncapsulate(existing.peerPub);
          kemCiphertextB64 = encapsulated.ciphertextB64;
          myPqSecretB64 = gpvCrypto.bytesToBase64(encapsulated.sharedSecret);
          myKemPeerPub = existing.peerPub;
        }
      }
    }

    const packets = gpvCrypto.makeKeyPackets(
      identity.publicKey,
      kemCiphertextB64
    );
    await sendRawPackets(packets);

    const updatedRecord = {
      ...(existing || {}),
      mode: "ecdh",
      peerPub: existing ? existing.peerPub || null : null,
      keyB64: existing ? existing.keyB64 || null : null,
      myKemCtB64: kemCiphertextB64 || (existing ? existing.myKemCtB64 || null : null),
      myPqSecretB64,
      myKemPeerPub,
      decapsulatedPqB64,
      pqSharedB64: decapsulatedPqB64 || myPqSecretB64 || (existing ? existing.pqSharedB64 || null : null),
      sentMyKey: true,
      verified: existing ? Boolean(existing.verified) : false,
      quantumSafe: Boolean(identity.quantumSafe),
    };

    await store.saveConversation(threadId, updatedRecord);
    keyCache.delete(threadId);
    await completeExchangeIfReady(threadId);
    await syncComposerState();
    return { ok: true };
  }

  async function processKeyMessages(threadId, entries) {
    const peerKeys = entries.filter((e) => !e.isOwn);
    if (peerKeys.length === 0) return;

    const newestEntry = peerKeys[peerKeys.length - 1];
    const newestPub = newestEntry.publicKeyB64;
    let newestKemCt = newestEntry.kemCiphertextB64 || null;
    if (!newestKemCt) {
      for (let i = peerKeys.length - 1; i >= 0; i--) {
        if (
          peerKeys[i].publicKeyB64 === newestPub &&
          peerKeys[i].kemCiphertextB64
        ) {
          newestKemCt = peerKeys[i].kemCiphertextB64;
          break;
        }
      }
    }

    const record = await store.getConversation(threadId);
    if (record && record.mode === "passphrase") return;

    const identity = await store.getIdentity();
    let decapsulatedB64 = record ? record.decapsulatedPqB64 || null : null;
    if (newestKemCt && identity && identity.privateJwk) {
      try {
        const sharedBytes = await gpvCrypto.pqDecapsulate(
          identity.privateJwk,
          newestKemCt
        );
        decapsulatedB64 = gpvCrypto.bytesToBase64(sharedBytes);
      } catch (err) {
        console.error("[VeilX] ML-KEM-768 decapsulation failed:", err);
      }
    }

    if (!record || !record.peerPub) {
      await store.saveConversation(threadId, {
        ...(record || {}),
        mode: "ecdh",
        peerPub: newestPub,
        keyB64: null,
        decapsulatedPqB64: decapsulatedB64,
        pqSharedB64: decapsulatedB64 || (record ? record.myPqSecretB64 || null : null),
        sentMyKey: record ? Boolean(record.sentMyKey) : false,
        verified: false,
        quantumSafe: newestEntry.quantumSafe,
      });
      keyCache.delete(threadId);

      if (record && record.sentMyKey) {
        if (
          !decapsulatedB64 &&
          !(record.myPqSecretB64 && record.myKemPeerPub === newestPub) &&
          newestEntry.quantumSafe &&
          !sending
        ) {
          await sendMyKey();
        } else {
          await completeExchangeIfReady(threadId);
        }
      } else {
        ui.showToast(
          "Your contact started a Quantum-Safe chat. Send your key to finish setting it up.",
          {
            kind: "info",
            actionLabel: "Send my key",
            timeoutMs: 0,
            onAction: () =>
              sendMyKey()
                .then((r) => {
                  if (!r.ok) ui.showToast(r.error, { kind: "error" });
                })
                .catch((err) => ui.showToast(err.message, { kind: "error" })),
          }
        );
      }
      await syncComposerState();
      return;
    }

    if (record.peerPub === newestPub) {
      if (decapsulatedB64 && record.decapsulatedPqB64 !== decapsulatedB64) {
        await store.saveConversation(threadId, {
          ...record,
          decapsulatedPqB64: decapsulatedB64,
          pqSharedB64: decapsulatedB64,
        });
        keyCache.delete(threadId);
        await completeExchangeIfReady(threadId);
        await syncComposerState();
      } else if (!record.keyB64) {
        await completeExchangeIfReady(threadId);
      }
      return;
    }

    if (record.peerPub !== newestPub) {
      const warnId = threadId + ":" + newestPub;
      if (warnedKeyChanges.has(warnId)) return;
      warnedKeyChanges.add(warnId);

      ui.showToast(
        "Your contact's key has changed (new device or reinstall?). Only accept it if you can confirm the new safety code with them another way.",
        {
          kind: "warning",
          actionLabel: "Use new key",
          timeoutMs: 0,
          onAction: async () => {
            try {
              await store.saveConversation(threadId, {
                mode: "ecdh",
                peerPub: newestPub,
                keyB64: null,
                altKeysB64: [],
                myKemCtB64: null,
                myPqSecretB64: null,
                myKemPeerPub: null,
                decapsulatedPqB64: decapsulatedB64,
                pqSharedB64: decapsulatedB64,
                sentMyKey: false,
                verified: false,
                quantumSafe: newestEntry.quantumSafe,
              });
              keyCache.delete(threadId);
              await sendMyKey();
              await syncComposerState();
            } catch (err) {
              ui.showToast("Could not switch to the new key: " + err.message, {
                kind: "error",
              });
            }
          },
        }
      );
    }
  }

  // ── Mounting & Updating VeilX's Composer ─────────────────────────────────

  async function syncComposerState() {
    const input = dom.findMessageInput();
    if (input) {
      dom.setNativeComposerHidden(input, Boolean(settings.enabled));
    }
    if (!activeComposer || !activeComposer.isConnected()) return;
    const threadId = dom.getThreadId();
    const record = threadId ? await store.getConversation(threadId) : null;
    activeComposer.updateState({
      enabled: settings.enabled,
      beautifyUi: settings.beautifyUi,
      requireVerification: settings.requireVerification,
      record,
      threadId,
    });
  }

  async function ensureOnPageComposer() {
    if (!dom.isDmPage()) {
      if (activeComposer) {
        activeComposer.remove();
        activeComposer = null;
        activeAnchorInput = null;
      }
      return;
    }

    const input = dom.findMessageInput();
    if (!input) return;

    dom.setNativeComposerHidden(input, Boolean(settings.enabled));

    const currentThreadId = dom.getThreadId();
    if (
      activeComposer &&
      activeComposer.isConnected() &&
      activeAnchorInput === input
    ) {
      if (lastThreadId !== currentThreadId) {
        lastThreadId = currentThreadId;
        await syncComposerState();
      }
      return;
    }

    if (activeComposer) {
      activeComposer.remove();
      activeComposer = null;
    }

    const anchorEl = dom.findComposerContainer(input) || input;
    activeAnchorInput = input;
    lastThreadId = currentThreadId;

    activeComposer = ui.renderComposer(anchorEl, {
      onSendText: async (text) => {
        const chunks = util.splitIntoChunks(text, util.MAX_PLAINTEXT_BYTES);
        const gid =
          chunks.length > 1
            ? gpvCrypto.bytesToBase64(crypto.getRandomValues(new Uint8Array(4)))
            : undefined;
        for (let i = 0; i < chunks.length; i++) {
          const chunkMeta =
            chunks.length > 1
              ? { gid, ci: i + 1, ct: chunks.length }
              : null;
          const ok = await encryptAndSendPlaintext(chunks[i], false, chunkMeta);
          if (!ok) return false;
          if (i < chunks.length - 1) await dom.wait(220);
        }
        return true;
      },
      onSendKey: async () => {
        try {
          const res = await sendMyKey();
          if (res.ok) {
            ui.showToast("ML-KEM-768 + P-256 key sent into the chat.", {
              kind: "info",
            });
          } else {
            ui.showToast(res.error || "Could not send key.", { kind: "error" });
          }
        } catch (err) {
          ui.showToast(err.message || "Could not send key.", { kind: "error" });
        }
      },
    });

    await syncComposerState();
  }

  // ── Scanning & Replacing Encrypted Messages in the Conversation ──────────

  let scanTimer = null;
  let scanning = false;
  let scanAgain = false;

  function scheduleScan() {
    if (!dom.isDmPage()) return;
    clearTimeout(scanTimer);
    scanTimer = setTimeout(runScan, 180);
  }

  async function runScan() {
    if (scanning) {
      scanAgain = true;
      return;
    }
    scanning = true;
    try {
      await ensureOnPageComposer();
      await scanMessages();
    } catch (err) {
      console.error("[VeilX] scan error:", err);
    } finally {
      scanning = false;
      if (scanAgain) {
        scanAgain = false;
        scheduleScan();
      }
    }
  }

  function extractBlob(text) {
    const cleaned = (text || "").replace(/[\u200B-\u200D\uFEFF\u00AD\s]+/g, "");
    const match = cleaned.match(/^GPV2:[A-Za-z0-9+/]+=*/);
    return match && match[0].length >= 45 ? match[0] : null;
  }

  async function scanMessages() {
    if (!dom.isDmPage()) return;
    currentScanPassId++;

    const input = dom.findMessageInput();
    const pane = dom.getConversationPane(input);
    const root = pane || document.body;
    const threadId = dom.getThreadId();

    const found = dom.findEncryptedElements(root, [MSG_PREFIX, KEY_PREFIX]);
    if (found.length === 0) return;

    const rawKeyTexts = [];
    for (const { el, text, handled } of found) {
      if (text.startsWith(KEY_PREFIX)) {
        if (!pane) continue;
        const parsedPart = gpvCrypto.parseKeyMessage(text);
        if (!parsedPart) continue;
        rawKeyTexts.push(text);
        if (!handled) {
          const isOwnPart = parsedPart.publicKeyB64
            ? await store.isOwnPublicKey(parsedPart.publicKeyB64)
            : false;
          ui.renderKeyLabel(
            el,
            isOwnPart,
            true,
            Boolean(parsedPart.kemCiphertextB64)
          );
        }
      }
    }

    if (threadId && rawKeyTexts.length > 0) {
      const reassembled = gpvCrypto.reassembleKeyPackets(rawKeyTexts);
      const keyEntries = [];
      for (const item of reassembled) {
        const isOwn = await store.isOwnPublicKey(item.publicKeyB64);
        keyEntries.push({
          ...item,
          b64: item.publicKeyB64,
          isOwn,
        });
      }
      if (keyEntries.length > 0) {
        await processKeyMessages(threadId, keyEntries);
      }
    }

    let decryptCount = 0;
    for (const { el, text, handled } of found) {
      if (!text.startsWith(KEY_PREFIX) && !handled) {
        if (decryptCount >= MAX_DECRYPTS_PER_SCAN) continue;
        const blob = extractBlob(text);
        if (!blob) continue;
        decryptCount++;
        const controller = ui.renderEncrypted(
          el,
          blob,
          (b) => decryptForThread(threadId, b, el),
          settings.autoDecrypt
        );
        pendingBubbles.add(controller);
      }
    }
  }

  function retryPending() {
    let count = 0;
    for (const controller of pendingBubbles) {
      if (!controller.isConnected()) {
        pendingBubbles.delete(controller);
      } else if (
        !controller.isRevealed() &&
        settings.autoDecrypt &&
        count < MAX_DECRYPTS_PER_SCAN
      ) {
        count++;
        controller.retry();
      }
    }
  }

  // ── Privileged Extension IPC Listener (Popup & Background Broker) ────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;
    if (
      !message ||
      ![
        "GPV_SEND_KEY",
        "GPV_SEND_CIPHERTEXT",
        "GPV_BROKER_SEND_KEY",
        "GPV_BROKER_SEND_CIPHERTEXT",
      ].includes(message.type)
    ) {
      return;
    }

    // Ignore in hidden Instagram helper subframes so only the frame with the active
    // DM conversation handles sending and calls `sendResponse`!
    if (!dom.isDmPage()) {
      return false;
    }

    if (
      message.type === "GPV_SEND_CIPHERTEXT" ||
      message.type === "GPV_BROKER_SEND_CIPHERTEXT"
    ) {
      sendCiphertext(message.ciphertext, message.threadId)
        .then(sendResponse)
        .catch((err) => sendResponse({ ok: false, error: err.message }));
      return true;
    }

    sendMyKey()
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: err.message }));

    return true;
  });

  // ── Reacting to Storage Changes ──────────────────────────────────────────

  chrome.storage.onChanged.addListener((changes) => {
    let keysChanged = false;

    for (const name of Object.keys(changes)) {
      if (name === "enabled") {
        settings.enabled = changes.enabled.newValue !== false;
      }
      if (name === "autoDecrypt") {
        settings.autoDecrypt = changes.autoDecrypt.newValue !== false;
      }
      if (name === "beautifyUi") {
        settings.beautifyUi = changes.beautifyUi.newValue !== false;
        dom.applyPageTheme(settings.beautifyUi);
      }
      if (name === "padMessages") {
        settings.padMessages = changes.padMessages.newValue !== false;
      }
      if (name === "requireVerification") {
        settings.requireVerification =
          changes.requireVerification.newValue === true;
      }
      if (name === "identity" || name === "vaultLocked") {
        keysChanged = true;
      }
      if (name.startsWith("conv:")) {
        const oldVal = changes[name].oldValue || {};
        const newVal = changes[name].newValue || {};
        const threadId = name.slice(5);

        // Update cached ownTokens in-place when we send a message so we don't clear
        // keyCache or trigger unnecessary DOM re-renders mid-send!
        if (keyCache.has(threadId) && keyCache.get(threadId)) {
          keyCache.get(threadId).ownTokens = Array.isArray(newVal.ownTokens)
            ? newVal.ownTokens
            : [];
        }

        if (
          oldVal.keyB64 !== newVal.keyB64 ||
          oldVal.pqSharedB64 !== newVal.pqSharedB64 ||
          oldVal.decapsulatedPqB64 !== newVal.decapsulatedPqB64 ||
          oldVal.peerPub !== newVal.peerPub ||
          oldVal.sentMyKey !== newVal.sentMyKey ||
          oldVal.verified !== newVal.verified ||
          oldVal.mode !== newVal.mode
        ) {
          keysChanged = true;
        }
      }
    }

    if (keysChanged) keyCache.clear();
    if (keysChanged || changes.autoDecrypt) retryPending();
    if (
      keysChanged ||
      changes.enabled ||
      changes.beautifyUi ||
      changes.requireVerification
    ) {
      syncComposerState().catch(() => {});
    }
  });

  // ── Start-up ─────────────────────────────────────────────────────────────

  attachNativeInterceptors();

  async function boot() {
    settings = await store.getSettings();
    dom.applyPageTheme(settings.beautifyUi);

    new MutationObserver(scheduleScan).observe(document.body, {
      childList: true,
      subtree: true,
    });
    scheduleScan();
  }

  boot().catch((err) => console.error("[VeilX] start-up failed:", err));
})();
