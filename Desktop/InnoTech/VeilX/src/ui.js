/**
 * src/ui.js — VeilX v5.0 UI Components:
 *   1. Encrypted / Decrypted message bubbles
 *   2. Key-exchange status badges (`ML-KEM-768`)
 *   3. Cross-Origin `chrome-extension://` Iframe Composer (communicating strictly
 *      via `chrome.runtime` — ZERO `window.parent.postMessage` listeners!)
 *   4. Purplish-Bluish Floating Notices (Toasts)
 */

globalThis.GPV = globalThis.GPV || {};

GPV.ui = (() => {
  "use strict";

  const HOST_ATTRIBUTE = "data-gpv-host";
  const COMPOSER_HOST_ATTRIBUTE = "data-gpv-composer-host";

  let sharedSheet = null;
  function getSheet() {
    if (!sharedSheet) {
      sharedSheet = new CSSStyleSheet();
      sharedSheet.replaceSync(GPV.styles.css);
    }
    return sharedSheet;
  }

  function createHost(tagName = "span", attr = HOST_ATTRIBUTE) {
    const host = document.createElement(tagName);
    host.setAttribute(attr, "1");
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.adoptedStyleSheets = [getSheet()];
    return { host, shadow };
  }

  function make(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function replaceElement(original, host) {
    original.setAttribute("data-gpv-handled", "1");
    original.style.display = "none";
    original.insertAdjacentElement("afterend", host);
  }

  // ── 1. Encrypted Message Bubble ──────────────────────────────────────────

  function renderEncrypted(original, blob, decryptFn, autoDecrypt) {
    const { host, shadow } = createHost();
    const bubble = make("div", "bubble");
    shadow.appendChild(bubble);

    let revealed = false;
    let busy = false;

    function show(statusClass, statusText, buttonLabel) {
      bubble.replaceChildren();
      bubble.appendChild(make("div", "status " + statusClass, statusText));
      if (buttonLabel) {
        const button = make("button", "button", buttonLabel);
        button.type = "button";
        button.addEventListener("click", attempt);
        bubble.appendChild(button);
      }
    }

    function showRevealed(plaintext, meta = {}) {
      revealed = true;
      bubble.replaceChildren();
      const statusRow = make("div", "status ok", "🔓 VeilX");
      if (meta.quantumSafe) {
        statusRow.appendChild(make("span", "pq-pill", "ML-KEM-768"));
      }
      if (meta.chunkLabel) {
        statusRow.appendChild(make("span", "pq-pill", meta.chunkLabel));
      }
      bubble.appendChild(statusRow);
      bubble.appendChild(make("div", "plain", plaintext));
    }

    async function attempt() {
      if (revealed || busy) return;
      busy = true;
      show("", "Decrypting…");
      try {
        const result = await decryptFn(blob);
        if (result.ok) {
          showRevealed(result.text, {
            quantumSafe: result.quantumSafe,
            chunkLabel: result.chunkLabel,
          });
        } else if (result.reason === "no-key") {
          show("", "🔒 Encrypted · No key set for this chat.", "Try again");
        } else if (result.reason === "vault-locked") {
          show("", "🔒 Encrypted · Unlock Vault in VeilX popup.", "Try again");
        } else if (result.reason === "replay") {
          show("error", "⚠ Blocked duplicate / replayed ciphertext.", null);
        } else {
          show(
            "error",
            "⚠ Could not decrypt: wrong key or damaged message.",
            "Try again"
          );
        }
      } catch (err) {
        console.error("[VeilX] decrypt error:", err);
        show("error", "⚠ Could not decrypt.", "Try again");
      } finally {
        busy = false;
      }
    }

    show("", "🔒 Encrypted message", "Decrypt");
    replaceElement(original, host);
    if (autoDecrypt) attempt();

    return {
      isConnected: () => host.isConnected,
      isRevealed: () => revealed,
      retry: () => attempt(),
    };
  }

  // ── 2. Key-Exchange Message Label ────────────────────────────────────────

  function renderKeyLabel(original, isOwn, isQuantumSafe = true, hasKemCapsule = false) {
    const { host, shadow } = createHost();
    const bubble = make("div", "bubble");
    const labelText = isOwn
      ? hasKemCapsule
        ? "🔑 Your ML-KEM-768 Capsule (sent)"
        : "🔑 Your ML-KEM-768 Key (sent)"
      : hasKemCapsule
      ? "🔑 Contact's ML-KEM-768 Capsule"
      : "🔑 Contact's ML-KEM-768 Key";
    const statusRow = make("div", "status ok", labelText);
    if (isQuantumSafe) {
      statusRow.appendChild(
        make("span", "pq-pill", hasKemCapsule ? "KEM-768" : "FIPS-203")
      );
    }
    bubble.appendChild(statusRow);
    shadow.appendChild(bubble);
    replaceElement(original, host);
  }

  // ── 3. VeilX Cross-Origin Extension Iframe Composer (Zero postMessage) ───

  function renderComposer(anchorEl, handlers) {
    const { host, shadow } = createHost("div", COMPOSER_HOST_ATTRIBUTE);

    const SHIELDED_EVENTS = [
      "keydown",
      "keyup",
      "keypress",
      "beforeinput",
      "input",
      "compositionstart",
      "compositionupdate",
      "compositionend",
      "paste",
      "copy",
      "cut",
    ];
    for (const evtName of SHIELDED_EVENTS) {
      window.addEventListener(
        evtName,
        (e) => {
          if (e.target === host) {
            e.stopImmediatePropagation();
          }
        },
        true
      );
    }

    const canUseExtensionIframe = Boolean(
      typeof chrome !== "undefined" &&
        chrome.runtime &&
        typeof chrome.runtime.getURL === "function"
    );

    let iframeEl = null;
    if (canUseExtensionIframe) {
      const wrap = make("div", "vx-iframe-wrap");
      iframeEl = document.createElement("iframe");
      iframeEl.className = "vx-composer-iframe";
      const tid = GPV.dom.getThreadId() || "";
      iframeEl.src =
        chrome.runtime.getURL("composer/composer.html") +
        `?threadId=${encodeURIComponent(tid)}`;
      iframeEl.setAttribute("title", "VeilX Secure Composer");
      iframeEl.setAttribute("allow", "clipboard-read; clipboard-write");
      wrap.appendChild(iframeEl);
      shadow.appendChild(wrap);
    }

    // Minimalist single-line fallback pill for synthetic test environments without iframes
    const shell = make("div", "vx-composer-shell");
    if (canUseExtensionIframe) shell.hidden = true;

    const statusBtn = make("button", "vx-chip-btn", "ML-KEM-768");
    statusBtn.type = "button";

    const textarea = make("textarea", "vx-textarea");
    textarea.rows = 1;
    textarea.placeholder = "Message securely with VeilX…";
    textarea.autocomplete = "off";
    textarea.spellcheck = false;

    const counter = make("span", "vx-counter", "0 B");
    const sendBtn = make("button", "vx-send-btn", "Send");
    sendBtn.type = "button";

    shell.append(statusBtn, textarea, counter, sendBtn);
    shadow.appendChild(shell);

    for (const evtName of SHIELDED_EVENTS) {
      textarea.addEventListener(
        evtName,
        (e) => {
          e.stopPropagation();
        },
        true
      );
      shell.addEventListener(
        evtName,
        (e) => {
          e.stopPropagation();
        },
        false
      );
    }

    function updateCounter() {
      const bytes = GPV.util.utf8ByteLength(textarea.value);
      counter.textContent = `${bytes} B`;
    }

    textarea.addEventListener("input", updateCounter);

    let busy = false;
    async function triggerSend() {
      if (busy) return;
      const text = textarea.value;
      if (!text.trim()) return;
      busy = true;
      sendBtn.disabled = true;
      try {
        const ok = await handlers.onSendText(text);
        if (ok) {
          textarea.value = "";
          updateCounter();
        }
      } finally {
        busy = false;
        sendBtn.disabled = false;
      }
    }

    textarea.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
        e.preventDefault();
        triggerSend();
      }
    });

    sendBtn.addEventListener("click", triggerSend);
    statusBtn.addEventListener("click", async () => {
      await handlers.onSendKey();
    });

    anchorEl.insertAdjacentElement("afterend", host);

    function updateState({ enabled, record, threadId, requireVerification }) {
      if (iframeEl && threadId) {
        const expectedSrc =
          chrome.runtime.getURL("composer/composer.html") +
          `?threadId=${encodeURIComponent(threadId)}`;
        if (iframeEl.src !== expectedSrc) {
          iframeEl.src = expectedSrc;
        }
      }

      if (!enabled) {
        host.hidden = true;
        return;
      }
      host.hidden = false;

      let nextLabel = "Exchange Key";
      if (record && record.keyB64) {
        if (record.mode === "ecdh" && requireVerification && !record.verified) {
          nextLabel = "Verify Key";
        } else {
          nextLabel =
            record.mode === "passphrase" ? "AES-256 Key" : "ML-KEM-768";
        }
      }
      if (statusBtn.textContent !== nextLabel) {
        statusBtn.textContent = nextLabel;
      }
    }

    return {
      host,
      isConnected: () => host.isConnected,
      updateState,
      getValue: () => textarea.value,
      setValue: (v) => {
        textarea.value = v;
        updateCounter();
      },
      focus: () => textarea.focus(),
      remove: () => host.remove(),
    };
  }

  // ── 4. Floating Notices (Toasts) ─────────────────────────────────────────

  let currentToast = null;
  let toastTimer = null;

  function dismissToast() {
    clearTimeout(toastTimer);
    if (currentToast) {
      currentToast.remove();
      currentToast = null;
    }
  }

  function showToast(message, options = {}) {
    const { kind = "info", actionLabel, onAction, timeoutMs = 7000 } = options;
    dismissToast();

    const { host, shadow } = createHost();
    host.style.position = "fixed";
    host.style.bottom = "24px";
    host.style.left = "50%";
    host.style.transform = "translateX(-50%)";
    host.style.zIndex = "2147483647";

    const toast = make("div", "toast " + kind);
    toast.setAttribute("role", "status");
    toast.appendChild(make("div", "toast-text", message));

    if (actionLabel && onAction) {
      const action = make("button", "toast-action", actionLabel);
      action.type = "button";
      action.addEventListener("click", () => {
        dismissToast();
        onAction();
      });
      toast.appendChild(action);
    }

    const close = make("button", "toast-close", "✕");
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss");
    close.addEventListener("click", dismissToast);
    toast.appendChild(close);

    shadow.appendChild(toast);
    document.body.appendChild(host);
    currentToast = host;

    if (timeoutMs > 0) {
      toastTimer = setTimeout(dismissToast, timeoutMs);
      if (toastTimer && typeof toastTimer.unref === "function") toastTimer.unref();
    }
  }

  return {
    renderEncrypted,
    renderKeyLabel,
    renderComposer,
    showToast,
    dismissToast,
  };
})();

if (typeof module !== "undefined") module.exports = GPV.ui;
