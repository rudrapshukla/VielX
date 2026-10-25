/**
 * popup/popup.js — VeilX v5.2.0 Control Center & Studio Launcher.
 */

(function () {
  "use strict";

  const gpvCrypto = GPV.crypto;
  const { store, util } = GPV;

  const $ = (id) => document.getElementById(id);

  let tabId = null;
  let threadId = null;
  let removeArmed = false;

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

    $("statusDot").className = settings.enabled ? "dot on" : "dot";
    $("statusText").textContent = settings.enabled
      ? "Encryption is on · ML-KEM-768"
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

    const record = await store.getConversation(threadId);
    const state = $("chatState");

    if (!record) {
      state.textContent =
        "No key yet. Set up a key below (or click Exchange Key directly in the chat bar).";
      $("setupCard").hidden = false;
      return;
    }

    if (record.keyB64) {
      $("removeBtn").hidden = false;
      if (record.mode === "passphrase") {
        state.textContent =
          "Ready. This chat uses a shared passphrase (AES-256-GCM). Type directly in the on-page VeilX chat bar.";
      } else {
        const isPq = record.quantumSafe !== false;
        const isVerified = Boolean(record.verified);
        const identity = await store.getIdentity();
        if (identity && record.peerPub) {
          $("safetyCode").textContent = await gpvCrypto.safetyCode(
            identity.publicKey,
            record.peerPub
          );
          $("safetyBox").hidden = false;
        }
        if (isVerified || !settings.requireVerification) {
          state.textContent = isPq
            ? "Ready. Protected by NIST FIPS 203 ML-KEM-768 + ECDH P-256. Type directly in the on-page VeilX chat bar."
            : "Ready. Protected by ECDH key exchange.";
          if ($("safetyHint")) {
            $("safetyHint").textContent = isVerified
              ? "Safety code verified for this conversation."
              : "Compare this 80-bit Safety Code with your contact anytime to confirm authenticity.";
          }
          if (!isVerified && $("verifyBtn")) {
            $("verifyBtn").hidden = false;
          }
        } else {
          state.textContent =
            "Pending verification. Compare the 80-bit Safety Code below with your contact, then click Verify safety code to unlock sending.";
          if ($("verifyBtn")) $("verifyBtn").hidden = false;
        }
      }
      return;
    }

    $("removeBtn").hidden = false;
    $("sendKeyBtn").hidden = false;
    if (record.peerPub && (!record.sentMyKey || !record.pqSharedB64)) {
      state.textContent =
        "Your contact's key has arrived. Send yours to encapsulate the ML-KEM-768 secret and finish.";
      $("sendKeyBtn").textContent = "Send my key";
    } else {
      state.textContent =
        "Your key was sent. Waiting for your contact to send theirs. They need VeilX too.";
      $("sendKeyBtn").textContent = "Send my key again";
    }
  }

  async function requestSendKey() {
    showMessage("", "");
    if (tabId === null) {
      showMessage("Open an Instagram chat first.", "error");
      return;
    }
    try {
      const reply = await chrome.tabs.sendMessage(tabId, {
        type: "GPV_SEND_KEY",
      });
      if (reply && reply.ok) {
        showMessage("ML-KEM-768 + P-256 key sent into the chat.", "ok");
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

    if (passphrase.length < 12) {
      showMessage(
        "Use at least 12 characters. Press Generate for a strong one.",
        "error"
      );
      return;
    }

    const button = $("savePassBtn");
    button.disabled = true;
    showMessage("Working out the key. This takes a moment.", "");
    try {
      const keyBytes = await gpvCrypto.deriveKeyFromPassphrase(passphrase);
      await store.saveConversation(threadId, {
        mode: "passphrase",
        keyB64: gpvCrypto.bytesToBase64(keyBytes),
        quantumSafe: true,
        verified: true,
      });
      $("passInput").value = "";
      showMessage(
        "Key saved. Your contact must enter the same passphrase.",
        "ok"
      );
    } catch (err) {
      console.error("[VeilX] save passphrase failed:", err);
      showMessage("Could not save the key.", "error");
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

  function openStudioApp() {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create && chrome.runtime && chrome.runtime.getURL) {
      chrome.tabs.create({ url: chrome.runtime.getURL("app/app.html") });
    } else if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: "GPV_OPEN_STUDIO_APP" });
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
      $("passInput").value = gpvCrypto.generatePassphrase();
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
