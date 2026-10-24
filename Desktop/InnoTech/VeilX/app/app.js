/**
 * app/app.js — Controller for the VeilX Studio Standalone Web App (`app/app.html`).
 */

(function () {
  "use strict";

  const gpvCrypto = GPV.crypto;
  const { store, util } = GPV;

  const $ = (id) => document.getElementById(id);
  let activeThreadId = null;

  function showNotice(text) {
    const el = $("studioNotice");
    el.textContent = text || "";
    el.hidden = !text;
  }

  function parseThreadIdInput(raw) {
    const val = (raw || "").trim();
    if (!val) return null;
    const fromUrl = util.threadIdFromUrl(val);
    if (fromUrl) return fromUrl;
    const match = val.match(/\/direct\/t\/([^/?#]+)/);
    if (match) return match[1];
    return val.replace(/[^a-zA-Z0-9_-]/g, "") || null;
  }

  async function renderStudio() {
    const settings = await store.getSettings();
    const vault = await store.getVaultStatus();

    $("studioMasterToggle").checked = settings.enabled;
    $("studioAutoDecrypt").checked = settings.autoDecrypt;
    $("studioBeautifyUi").checked = settings.beautifyUi;
    $("studioPadMessages").checked = settings.padMessages;

    $("studioStatusDot").className = settings.enabled ? "status-dot on" : "status-dot";
    $("studioStatusText").textContent = settings.enabled
      ? "Encryption Active (ML-KEM-768)"
      : "Encryption Paused";

    $("studioVaultBadge").textContent = vault.locked ? "Locked" : "Unlocked";
    $("studioVaultActionBtn").textContent = vault.locked ? "Unlock" : "Lock";

    // List all secured conversations from storage
    const all = await chrome.storage.local.get(null);
    const convEntries = Object.entries(all)
      .filter(([k]) => k.startsWith("conv:"))
      .map(([k, v]) => ({ threadId: k.slice(5), record: v }));

    $("chatCountBadge").textContent = String(convEntries.length);
    const listEl = $("securedThreadsList");
    listEl.replaceChildren();

    if (convEntries.length === 0) {
      const p = document.createElement("p");
      p.className = "empty-hint";
      p.textContent = vault.locked
        ? "Vault is locked. Unlock below to view secured chats."
        : "No conversation keys saved yet.";
      listEl.appendChild(p);
    } else {
      for (const { threadId, record } of convEntries) {
        const row = document.createElement("div");
        row.className = "thread-item";
        const idSpan = document.createElement("span");
        idSpan.className = "thread-item-id";
        idSpan.textContent = "Chat " + util.shortId(threadId);
        const modeSpan = document.createElement("span");
        modeSpan.className = "thread-item-mode";
        modeSpan.textContent =
          record.mode === "passphrase"
            ? "Passphrase · AES-256"
            : record.keyB64
            ? "ML-KEM-768 + P-256"
            : "Handshake pending";
        row.append(idSpan, modeSpan);
        row.addEventListener("click", () => {
          activeThreadId = threadId;
          $("threadInput").value = threadId;
          const targetUrl = `https://www.instagram.com/direct/t/${threadId}/`;
          $("igWorkspaceFrame").src = targetUrl;
          $("workspaceUrlLabel").textContent = targetUrl;
          renderStudio();
        });
        listEl.appendChild(row);
      }
    }

    // Active thread details
    if (!activeThreadId) {
      $("activeThreadBadge").textContent = "None selected";
      $("threadKeyActions").hidden = true;
      return;
    }

    $("activeThreadBadge").textContent = util.shortId(activeThreadId);
    const record = await store.getConversation(activeThreadId);
    if (!record) {
      $("activeThreadDesc").textContent =
        "No key set for this chat yet. Save a passphrase below or click Exchange Key inside the chat bar.";
      $("threadKeyActions").hidden = true;
      return;
    }

    $("threadKeyActions").hidden = false;
    if (record.keyB64) {
      $("activeThreadDesc").textContent =
        record.mode === "passphrase"
          ? "Secured with 256-bit shared passphrase key."
          : "Secured with NIST FIPS 203 ML-KEM-768 + ECDH P-256 Hybrid key.";
      const identity = await store.getIdentity();
      if (record.mode === "ecdh" && identity && record.peerPub) {
        $("studioSafetyCode").textContent = await gpvCrypto.safetyCode(
          identity.publicKey,
          record.peerPub
        );
        $("studioSafetyBox").hidden = false;
        $("studioVerifyBtn").hidden = Boolean(record.verified);
      } else {
        $("studioSafetyBox").hidden = true;
        $("studioVerifyBtn").hidden = true;
      }
    } else {
      $("activeThreadDesc").textContent =
        "Key exchange in progress — open the chat on the right to complete.";
      $("studioSafetyBox").hidden = true;
      $("studioVerifyBtn").hidden = true;
    }
  }

  function wireEvents() {
    $("studioMasterToggle").addEventListener("change", async (e) => {
      await store.setSetting("enabled", e.target.checked);
      await renderStudio();
    });
    $("studioAutoDecrypt").addEventListener("change", async (e) => {
      await store.setSetting("autoDecrypt", e.target.checked);
    });
    $("studioBeautifyUi").addEventListener("change", async (e) => {
      await store.setSetting("beautifyUi", e.target.checked);
    });
    $("studioPadMessages").addEventListener("change", async (e) => {
      await store.setSetting("padMessages", e.target.checked);
    });

    $("loadThreadBtn").addEventListener("click", async () => {
      const tid = parseThreadIdInput($("threadInput").value);
      if (!tid) return;
      activeThreadId = tid;
      const targetUrl = `https://www.instagram.com/direct/t/${tid}/`;
      $("igWorkspaceFrame").src = targetUrl;
      $("workspaceUrlLabel").textContent = targetUrl;
      await renderStudio();
    });

    $("studioGenPassBtn").addEventListener("click", () => {
      $("studioPassInput").type = "text";
      $("studioPassInput").value = gpvCrypto.generatePassphrase();
      showNotice("Generated 100-bit passphrase. Copy it before saving.");
    });

    $("studioCopyPassBtn").addEventListener("click", async () => {
      const val = $("studioPassInput").value;
      if (!val) return;
      try {
        await navigator.clipboard.writeText(val);
        showNotice("Passphrase copied to clipboard.");
      } catch (_) {}
    });

    $("studioSavePassBtn").addEventListener("click", async () => {
      const tid = activeThreadId || parseThreadIdInput($("threadInput").value);
      if (!tid) {
        showNotice("Enter or select a Thread ID first.");
        return;
      }
      const phrase = $("studioPassInput").value.trim();
      if (phrase.length < 12) {
        showNotice("Passphrase must be at least 12 characters.");
        return;
      }
      activeThreadId = tid;
      $("studioSavePassBtn").disabled = true;
      try {
        const keyBytes = await gpvCrypto.deriveKeyFromPassphrase(phrase);
        await store.saveConversation(tid, {
          mode: "passphrase",
          keyB64: gpvCrypto.bytesToBase64(keyBytes),
          quantumSafe: true,
          verified: true,
        });
        $("studioPassInput").value = "";
        $("studioPassInput").type = "password";
        showNotice("Passphrase key saved for chat " + util.shortId(tid) + ".");
        await renderStudio();
      } finally {
        $("studioSavePassBtn").disabled = false;
      }
    });

    $("studioVerifyBtn").addEventListener("click", async () => {
      if (!activeThreadId) return;
      await store.verifyConversation(activeThreadId);
      showNotice("Safety code verified.");
      await renderStudio();
    });

    $("studioRemoveKeyBtn").addEventListener("click", async () => {
      if (!activeThreadId) return;
      await store.removeConversation(activeThreadId);
      showNotice("Key removed for chat " + util.shortId(activeThreadId) + ".");
      await renderStudio();
    });

    $("studioVaultActionBtn").addEventListener("click", async () => {
      const vault = await store.getVaultStatus();
      const pass = $("studioVaultInput").value.trim();
      if (pass.length < 12) {
        showNotice("Master passphrase must be at least 12 characters.");
        return;
      }
      $("studioVaultActionBtn").disabled = true;
      try {
        if (vault.locked) {
          await store.unlockVault(pass);
          showNotice("Vault unlocked.");
        } else {
          await store.lockVault(pass);
          showNotice("Vault locked and encrypted at rest.");
        }
        $("studioVaultInput").value = "";
        await renderStudio();
      } catch (err) {
        showNotice(err.message || "Vault operation failed.");
      } finally {
        $("studioVaultActionBtn").disabled = false;
      }
    });

    $("reloadFrameBtn").addEventListener("click", () => {
      const frame = $("igWorkspaceFrame");
      frame.src = frame.src;
    });

    $("openIgTabBtn").addEventListener("click", () => {
      const url = $("igWorkspaceFrame").src || "https://www.instagram.com/direct/inbox/";
      window.open(url, "_blank", "noopener");
    });

    chrome.storage.onChanged.addListener(() => renderStudio());
  }

  async function init() {
    wireEvents();
    await renderStudio();
  }

  init().catch((err) => console.error("[VeilX] Studio init error:", err));
})();
