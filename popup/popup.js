/**
 * popup/popup.js — VeilX v1.0.0 Control Center & Studio Launcher.
 */

(function () {
  "use strict";

  const vxCrypto = VX.crypto;
  const { store, util, session } = VX;

  const $ = (id) => document.getElementById(id);

  let tabId = null;
  let threadId = null;
  let removeArmed = false;
  let pendingOffer = false;

  function showMessage(text, kind) {
    const box = $("message");
    box.textContent = text;
    box.className = "message " + (kind || "");
    box.hidden = !text;
  }

  async function readActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    tabId = tab ? tab.id : null;
    threadId = tab && tab.url ? util.threadIdFromUrl(tab.url) : null;
  }

  async function render() {
    const settings = await store.getSettings();
    const vault = await store.getVaultStatus();

    $("masterToggle").checked = settings.enabled;
    $("autoToggle").checked = settings.autoDecrypt;
    if ($("verifyToggle")) $("verifyToggle").checked = settings.requireVerification;
    if ($("beautifyToggle")) $("beautifyToggle").checked = settings.beautifyUi;
    if ($("padToggle")) $("padToggle").checked = settings.padMessages;
    if ($("relayUrlInput") && document.activeElement !== $("relayUrlInput")) {
      $("relayUrlInput").value = settings.relayUrl || store.DEFAULT_RELAY_URL;
    }

    $("statusDot").className = settings.enabled ? "dot on" : "dot";
    $("statusText").textContent = settings.enabled
      ? "Encryption is on"
      : "Encryption is off";

    if ($("vaultBadge")) {
      $("vaultBadge").textContent = vault.locked ? "Locked" : "Unlocked";
      $("vaultBadge").className = vault.locked ? "vault-pill locked" : "vault-pill";
      $("lockVaultBtn").hidden = vault.locked;
      $("unlockVaultBtn").hidden = !vault.locked;
      $("vaultStateText").textContent = vault.locked
        ? "All conversation keys and private keys are AES-256-GCM encrypted at rest. Enter your master passphrase to unlock."
        : "Seal your saved keys on disk with an AES-256-GCM master passphrase when away.";
    }

    for (const id of [
      "noChatCard",
      "chatCard",
      "setupCard",
      "safetyBox",
      "verifyBtn",
      "sendKeyBtn",
      "removeBtn",
    ]) {
      if ($(id)) $(id).hidden = true;
    }
    removeArmed = false;
    $("removeBtn").textContent = "Remove key";

    if (!threadId) {
      $("noChatCard").hidden = false;
      return;
    }

    $("chatCard").hidden = false;
    $("chatId").textContent = util.shortId(threadId);

    if (vault.locked) {
      $("chatState").textContent =
        "Vault is currently locked. Unlock your Key Vault below to read or send messages.";
      return;
    }

    const status = await session.getStatus(threadId);
    const state = $("chatState");

    pendingOffer = false;
    if (tabId !== null) {
      try {
        const q = await chrome.tabs.sendMessage(tabId, { type: "VX_QUERY" });
        pendingOffer = Boolean(q && q.ok && q.offer);
      } catch (_) {}
    }

    if (status.state === "none") {
      if (pendingOffer) {
        state.textContent = "Your contact sent a key-exchange offer. Accept it to start a quantum-safe chat.";
        $("sendKeyBtn").textContent = "Accept contact's offer";
        $("sendKeyBtn").hidden = false;
      } else {
        state.textContent = "No key yet. Start a key exchange below (or click Exchange Key in the chat bar).";
      }
      $("setupCard").hidden = false;
      return;
    }

    $("removeBtn").hidden = false;

    if (status.state === "passphrase") {
      state.textContent =
        "Ready. This chat uses a shared passphrase (AES-256-GCM). It has NO forward secrecy: anyone who gets the passphrase can read everything. Prefer a key exchange.";
      return;
    }

    if (status.state === "offered") {
      state.textContent = "Your key offer was posted. Waiting for your contact to accept (they need VeilX too).";
      $("sendKeyBtn").textContent = "Send a new offer";
      $("sendKeyBtn").hidden = false;
      return;
    }

    // established
    $("safetyCode").textContent = status.safetyCode || "";
    $("safetyBox").hidden = !status.safetyCode;
    if (status.verified) {
      state.textContent =
        "Ready. Quantum-safe hybrid key (ML-KEM-768 + ephemeral P-256) with forward secrecy. Safety code verified.";
      if ($("safetyHint")) $("safetyHint").textContent = "Verified. Start a new exchange any time to refresh the keys.";
    } else {
      state.textContent = settings.requireVerification
        ? "Pending verification. Compare the Safety Code below with your contact over a channel Instagram does not control (voice call, in person), then confirm. Sending is blocked until you do."
        : "Ready, but NOT verified. Without comparing the Safety Code, someone controlling the chat could be impersonating your contact.";
      if ($("verifyBtn")) $("verifyBtn").hidden = false;
    }
    $("sendKeyBtn").textContent = pendingOffer ? "Accept contact's new offer" : "Start a new key exchange";
    $("sendKeyBtn").hidden = false;
  }

  async function requestSendKey() {
    showMessage("", "");
    if (tabId === null) {
      showMessage("Open an Instagram chat first.", "error");
      return;
    }
    try {
      const reply = await chrome.tabs.sendMessage(tabId, {
        type: pendingOffer ? "VX_ACCEPT_OFFER" : "VX_START_EXCHANGE",
      });
      if (reply && reply.ok) {
        showMessage(
          pendingOffer
            ? "Reply sent. Now compare the Safety Code with your contact."
            : "Key offer sent into the chat. Waiting for your contact.",
          "ok"
        );
      } else {
        showMessage(
          (reply && reply.error) || "Could not send the key.",
          "error"
        );
      }
    } catch (err) {
      showMessage(
        "Could not reach the page. Reload the Instagram tab and try again.",
        "error"
      );
    }
    await render();
  }

  async function verifyCurrentChat() {
    showMessage("", "");
    if (!threadId) return;
    await store.verifyConversation(threadId);
    showMessage("Safety code verified.", "ok");
    await render();
  }

  async function savePassphrase() {
    showMessage("", "");
    const passphrase = $("passInput").value.trim();
    if (!vxCrypto.normalizePassphrase(passphrase)) {
      showMessage("Use a passphrase generated by VeilX (press Generate). Self-chosen phrases are not accepted: they can be guessed offline.", "error");
      return;
    }
    const button = $("savePassBtn");
    button.disabled = true;
    showMessage("Working out the key. This takes a moment.", "");
    try {
      await session.setPassphrase(threadId, passphrase);
      $("passInput").value = "";
      showMessage("Key saved. Your contact must enter the same passphrase.", "ok");
    } catch (err) {
      console.error("[VeilX] save passphrase failed:", err);
      showMessage(err.message || "Could not save the key.", "error");
    } finally {
      button.disabled = false;
    }
    await render();
  }

  async function removeKey() {
    if (!removeArmed) {
      removeArmed = true;
      $("removeBtn").textContent = "Click again to confirm";
      return;
    }
    await store.removeConversation(threadId);
    showMessage("Key removed for this chat.", "ok");
    await render();
  }

  async function handleLockVault() {
    showMessage("", "");
    const pass = $("vaultPassInput").value.trim();
    if (pass.length < 12) {
      showMessage("Vault master passphrase must be at least 12 characters.", "error");
      return;
    }
    $("lockVaultBtn").disabled = true;
    try {
      await store.lockVault(pass);
      $("vaultPassInput").value = "";
      showMessage("Vault locked. All keys encrypted at rest.", "ok");
      await render();
    } catch (err) {
      showMessage(err.message || "Could not lock vault.", "error");
    } finally {
      $("lockVaultBtn").disabled = false;
    }
  }

  async function handleUnlockVault() {
    showMessage("", "");
    const pass = $("vaultPassInput").value.trim();
    if (!pass) {
      showMessage("Enter your master passphrase to unlock.", "error");
      return;
    }
    $("unlockVaultBtn").disabled = true;
    try {
      await store.unlockVault(pass);
      $("vaultPassInput").value = "";
      showMessage("Vault unlocked.", "ok");
      await render();
    } catch (err) {
      showMessage("Wrong master passphrase or corrupted vault.", "error");
    } finally {
      $("unlockVaultBtn").disabled = false;
    }
  }

  async function handleSaveRelay() {
    showMessage("", "");
    const raw = ($("relayUrlInput") ? $("relayUrlInput").value : "").trim();
    if (!raw) {
      await store.setSetting("relayUrl", store.DEFAULT_RELAY_URL);
      showMessage("Reset to default relay URL.", "ok");
      await render();
      return;
    }
    try {
      const parsed = new URL(raw);
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        throw new Error("Relay URL must start with https:// or http://");
      }
      await store.setSetting("relayUrl", raw.replace(/\/+$/, ""));
      showMessage("Zero-Knowledge Relay URL saved.", "ok");
      await render();
    } catch (err) {
      showMessage(err.message || "Invalid Relay URL.", "error");
    }
  }

  function openStudioApp(e) {
    if (e && typeof e.preventDefault === "function") e.preventDefault();
    if (typeof chrome !== "undefined" && chrome.tabs && typeof chrome.tabs.create === "function") {
      chrome.tabs.create({ url: "https://veilxweb.onrender.com" });
    } else if (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.sendMessage === "function") {
      chrome.runtime.sendMessage({ type: "VX_OPEN_WEB_APP", url: "https://veilxweb.onrender.com" });
    }
  }

  function selectTab(which) {
    const passActive = which === "pass";
    $("tabPass").classList.toggle("is-active", passActive);
    $("tabKex").classList.toggle("is-active", !passActive);
    $("tabPass").setAttribute("aria-selected", String(passActive));
    $("tabKex").setAttribute("aria-selected", String(!passActive));
    $("panelPass").hidden = !passActive;
    $("panelKex").hidden = passActive;
  }

  function wireEvents() {
    $("masterToggle").addEventListener("change", async (e) => {
      await store.setSetting("enabled", e.target.checked);
      await render();
    });

    $("autoToggle").addEventListener("change", async (e) => {
      await store.setSetting("autoDecrypt", e.target.checked);
    });

    if ($("verifyToggle")) {
      $("verifyToggle").addEventListener("change", async (e) => {
        await store.setSetting("requireVerification", e.target.checked);
        await render();
      });
    }

    if ($("beautifyToggle")) {
      $("beautifyToggle").addEventListener("change", async (e) => {
        await store.setSetting("beautifyUi", e.target.checked);
      });
    }

    if ($("padToggle")) {
      $("padToggle").addEventListener("change", async (e) => {
        await store.setSetting("padMessages", e.target.checked);
      });
    }

    if ($("openStudioBtn")) {
      $("openStudioBtn").addEventListener("click", openStudioApp);
    }

    $("tabPass").addEventListener("click", () => selectTab("pass"));
    $("tabKex").addEventListener("click", () => selectTab("kex"));

    $("genBtn").addEventListener("click", () => {
      $("passInput").value = vxCrypto.generatePassphrase();
      showMessage(
        "Passphrase generated. Copy it and share it safely before saving.",
        ""
      );
    });

    $("copyBtn").addEventListener("click", async () => {
      const value = $("passInput").value;
      if (!value) {
        showMessage("Nothing to copy yet.", "error");
        return;
      }
      try {
        await navigator.clipboard.writeText(value);
        showMessage("Copied.", "ok");
      } catch (err) {
        showMessage(
          "Could not copy. Select the text and copy it manually.",
          "error"
        );
      }
    });

    $("savePassBtn").addEventListener("click", savePassphrase);
    $("startKexBtn").addEventListener("click", requestSendKey);
    $("sendKeyBtn").addEventListener("click", requestSendKey);
    if ($("verifyBtn")) $("verifyBtn").addEventListener("click", verifyCurrentChat);
    $("removeBtn").addEventListener("click", removeKey);
    if ($("lockVaultBtn")) $("lockVaultBtn").addEventListener("click", handleLockVault);
    if ($("unlockVaultBtn")) $("unlockVaultBtn").addEventListener("click", handleUnlockVault);
    if ($("saveRelayBtn")) $("saveRelayBtn").addEventListener("click", handleSaveRelay);

    chrome.storage.onChanged.addListener(() => render());
  }

  async function init() {
    wireEvents();
    await readActiveTab();
    await render();
  }

  init().catch((err) => {
    console.error("[VeilX] popup failed:", err);
    showMessage("Something went wrong opening the popup.", "error");
  });
})();
