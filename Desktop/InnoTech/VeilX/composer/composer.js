/**
 * composer/composer.js — Privileged Extension-Origin Composer Logic (VeilX v5.2.0).
 */

(function () {
  "use strict";

  const gpvCrypto = GPV.crypto;
  const { store, util } = GPV;

  const $ = (id) => document.getElementById(id);

  let threadId = new URLSearchParams(location.search).get("threadId") || null;

  function sendViaExtensionBroker(payload) {
    return new Promise((resolve) => {
      if (
        typeof chrome === "undefined" ||
        !chrome.runtime ||
        typeof chrome.runtime.sendMessage !== "function"
      ) {
        resolve({ ok: false, error: "Extension runtime unavailable." });
        return;
      }
      try {
        const maybePromise = chrome.runtime.sendMessage(payload, (reply) => {
          resolve(reply || { ok: false });
        });
        if (maybePromise && typeof maybePromise.then === "function") {
          maybePromise.then(
            (res) => resolve(res || { ok: false }),
            (err) => resolve({ ok: false, error: err.message })
          );
        }
      } catch (err) {
        resolve({ ok: false, error: err.message });
      }
    });
  }

  function updateByteCounter() {
    const text = $("composeInput").value;
    const bytes = util.utf8ByteLength(text);
    const chunks = Math.max(1, Math.ceil(bytes / util.MAX_PLAINTEXT_BYTES));
    const counter = $("byteCounter");
    if (chunks === 1) {
      counter.textContent = `${bytes} B`;
      counter.className = "vx-counter" + (bytes > 560 ? " warn" : "");
    } else {
      counter.textContent = `${bytes} B · ${chunks} parts`;
      counter.className = "vx-counter warn";
    }
    const ta = $("composeInput");
    ta.style.height = "auto";
    ta.style.height = Math.min(96, Math.max(22, ta.scrollHeight)) + "px";
  }

  async function renderState() {
    const settings = await store.getSettings();
    const vault = await store.getVaultStatus();
    const record = threadId ? await store.getConversation(threadId) : null;

    const btn = $("statusBtn");
    const label = $("statusLabel");
    const input = $("composeInput");

    if (vault.locked) {
      btn.className = "vx-badge-btn needs-action";
      label.textContent = "Vault Locked";
      input.placeholder = "Unlock your Key Vault in the VeilX toolbar icon…";
      return;
    }

    if (record && record.keyB64) {
      if (
        record.mode === "ecdh" &&
        settings.requireVerification &&
        !record.verified
      ) {
        btn.className = "vx-badge-btn needs-action";
        label.textContent = "Verify Key";
        input.placeholder = "Click Verify Key on the left (or in popup) to unlock…";
      } else {
        btn.className = "vx-badge-btn";
        label.textContent =
          record.mode === "passphrase" ? "AES-256 Key" : "ML-KEM-768";
        input.placeholder = "Message securely with VeilX…";
      }
      return;
    }

    btn.className = "vx-badge-btn needs-action";
    if (record && record.peerPub && (!record.sentMyKey || !record.pqSharedB64)) {
      label.textContent = "Accept PQ Key";
      input.placeholder = "Click Accept PQ Key on the left to finish setup…";
    } else if (record && record.sentMyKey && !record.peerPub) {
      label.textContent = "Waiting for Peer…";
      input.placeholder = "Your ML-KEM-768 key was sent — waiting for contact…";
    } else {
      label.textContent = "Exchange Key";
      input.placeholder = "Click Exchange Key on the left (or set passphrase in popup)…";
    }
  }

  let sending = false;
  async function encryptAndSend() {
    if (sending) return;
    const rawText = $("composeInput").value;
    const trimmed = rawText.trim();
    if (!trimmed || !threadId) return;

    const vault = await store.getVaultStatus();
    if (vault.locked) return;

    const settings = await store.getSettings();
    if (!settings.enabled) return;

    const record = await store.getConversation(threadId);
    if (!record || !record.keyB64) {
      // Automatically trigger key exchange if the user hasn't set up a key yet
      await sendViaExtensionBroker({
        type: "GPV_BROKER_SEND_KEY",
        threadId,
      });
      await renderState();
      return;
    }

    if (
      record.mode === "ecdh" &&
      settings.requireVerification &&
      !record.verified
    ) {
      return;
    }

    sending = true;
    $("sendBtn").disabled = true;

    try {
      const key = await gpvCrypto.importAesKey(
        gpvCrypto.base64ToBytes(record.keyB64)
      );
      const chunks = util.splitIntoChunks(trimmed, util.MAX_PLAINTEXT_BYTES);
      const groupId =
        chunks.length > 1
          ? gpvCrypto.bytesToBase64(crypto.getRandomValues(new Uint8Array(4)))
          : undefined;

      for (let i = 0; i < chunks.length; i++) {
        const seq = await store.allocateNextSeq(threadId);
        const msgId = gpvCrypto.bytesToBase64(
          crypto.getRandomValues(new Uint8Array(8))
        );
        await store.recordOwnSentToken(threadId, msgId);

        // NOTE: Do NOT bind local URL `threadId` as AES-GCM `aad`, because Instagram
        // Direct URLs (`/direct/t/<id>/`) often assign different viewer-scoped thread IDs
        // to the sender and receiver accounts for the same 1-on-1 conversation!
        const ciphertext = await gpvCrypto.encryptMessage(key, chunks[i], {
          pad: settings.padMessages,
          envelope: {
            seq,
            ts: Date.now(),
            id: msgId,
            gid: groupId,
            ci: chunks.length > 1 ? i + 1 : undefined,
            ct: chunks.length > 1 ? chunks.length : undefined,
          },
        });

        const res = await sendViaExtensionBroker({
          type: "GPV_BROKER_SEND_CIPHERTEXT",
          ciphertext,
          threadId,
        });
        if (!res || !res.ok) {
          throw new Error((res && res.error) || "Could not send ciphertext.");
        }
      }

      $("composeInput").value = "";
      updateByteCounter();
    } catch (err) {
      console.error("[VeilX] send failed:", err);
    } finally {
      sending = false;
      $("sendBtn").disabled = false;
      $("composeInput").focus();
    }
  }

  function wireEvents() {
    $("composeInput").addEventListener("input", updateByteCounter);

    $("composeInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
        e.preventDefault();
        encryptAndSend();
      }
    });

    $("sendBtn").addEventListener("click", encryptAndSend);

    $("statusBtn").addEventListener("click", async () => {
      if (!threadId) return;
      const settings = await store.getSettings();
      const record = await store.getConversation(threadId);
      if (
        record &&
        record.keyB64 &&
        record.mode === "ecdh" &&
        settings.requireVerification &&
        !record.verified
      ) {
        await store.verifyConversation(threadId);
        await renderState();
        return;
      }
      if (!record || !record.keyB64) {
        $("statusBtn").disabled = true;
        try {
          await sendViaExtensionBroker({
            type: "GPV_BROKER_SEND_KEY",
            threadId,
          });
        } finally {
          $("statusBtn").disabled = false;
          await renderState();
        }
      }
    });

    if (
      typeof chrome !== "undefined" &&
      chrome.runtime &&
      chrome.runtime.onMessage
    ) {
      chrome.runtime.onMessage.addListener((message, sender) => {
        if (sender.id !== chrome.runtime.id) return;
        if (message && message.type === "GPV_ACTIVE_THREAD_CHANGED") {
          threadId = message.threadId || null;
          renderState();
        }
      });
    }

    chrome.storage.onChanged.addListener(() => renderState());
  }

  async function init() {
    wireEvents();
    await renderState();
  }

  init().catch((err) => console.error("[VeilX] composer init failed:", err));
})();
