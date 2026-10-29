/**
 * src/ui.js — VeilX v1.0.0 UI Components:
 *   1. Encrypted / Decrypted message, Original-Fidelity Image, Short Video, and Voice Note bubbles
 *   2. Key-exchange status badges (`ML-KEM-768`)
 *   3. Cross-Origin `chrome-extension://` Iframe Composer (communicating strictly
 *      via `chrome.runtime` — ZERO `window.parent.postMessage` listeners!)
 *   4. Purplish-Bluish Floating Notices (Toasts)
 */

globalThis.VX = globalThis.VX || {};

VX.ui = (() => {
  "use strict";

  const HOST_ATTRIBUTE = "data-vx-host";
  const COMPOSER_HOST_ATTRIBUTE = "data-vx-composer-host";
  const SAFE_MEDIA_DATA_URL_RE =
    /^data:((?:image\/(?:webp|png|jpeg|jpg|gif))|(?:video\/(?:mp4|webm|quicktime))|(?:audio\/(?:webm|ogg|mp4|mpeg|mp3|wav|x-m4a)))(?:;codecs=[^;,]+)?;base64,[A-Za-z0-9+/=\s]+$/i;

  let sharedSheet = null;
  function getSheet() {
    if (!sharedSheet) {
      sharedSheet = new CSSStyleSheet();
      sharedSheet.replaceSync(VX.styles.css);
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
    original.setAttribute("data-vx-handled", "1");
    original.style.display = "none";
    original.insertAdjacentElement("afterend", host);
  }

  // ── 1. Encrypted Message & Media Bubble (Images, Videos, Voice Notes) ────

  const FAILURE_TEXT = {
    "no-key": ["", "🔒 Encrypted · No key set for this chat.", "Try again"],
    locked: ["", "🔒 Encrypted · Unlock the Vault in the VeilX popup.", "Try again"],
    replay: ["error", "⚠ Blocked: this message was already received (replay).", null],
    "own-unavailable": ["", "🔒 Sent by you · plaintext not kept on this device.", null],
    "too-far": ["error", "⚠ Blocked: message out of range for this chat.", null],
    "unknown-sender": ["error", "⚠ Blocked: message from an unknown sender.", null],
    malformed: ["error", "⚠ Damaged encrypted message.", null],
    bad: ["error", "⚠ Could not decrypt: wrong key, other chat, or tampered message.", "Try again"],
  };

  function renderEncrypted(original, blob, decryptFn, autoDecrypt) {
    const { host, shadow } = createHost();
    const bubble = make("div", "bubble");
    shadow.appendChild(bubble);

    let revealed = false;
    let busy = false;
    let collapsed = false;

    function setCollapsed(nextCollapsed) {
      collapsed = Boolean(nextCollapsed);
      host.hidden = collapsed;
      host.style.display = collapsed ? "none" : "";
      if (collapsed) {
        host.setAttribute("data-vx-collapsed-chunk", "1");
      } else {
        host.removeAttribute("data-vx-collapsed-chunk");
      }
      const parent = original && original.parentElement;
      if (parent && parent.children && parent.children.length <= 2) {
        if (collapsed) parent.setAttribute("data-vx-collapsed-chunk", "1");
        else parent.removeAttribute("data-vx-collapsed-chunk");
      }
    }

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
      setCollapsed(false);
      bubble.replaceChildren();
      const statusRow = make("div", "status ok", "🔓 VeilX");
      if (meta.badge) statusRow.appendChild(make("span", "pq-pill", meta.badge));
      if (meta.chunkLabel) statusRow.appendChild(make("span", "pq-pill", meta.chunkLabel));
      bubble.appendChild(statusRow);
      bubble.appendChild(make("div", "plain", plaintext));
    }

    function showProgress(progressText, meta = {}) {
      setCollapsed(false);
      bubble.replaceChildren();
      const statusRow = make("div", "status ok", "🔓 VeilX Media");
      if (meta.badge) statusRow.appendChild(make("span", "pq-pill", meta.badge));
      bubble.appendChild(statusRow);
      const pill = make("div", "vx-progress-pill");
      pill.appendChild(make("div", "vx-progress-label", progressText));
      const track = make("div", "vx-progress-track");
      const fill = make("div", "vx-progress-fill");
      const pct = Number.isFinite(meta.percent) ? Math.max(8, Math.min(100, Math.round(meta.percent))) : 60;
      fill.style.width = `${pct}%`;
      track.appendChild(fill);
      pill.appendChild(track);
      bubble.appendChild(pill);
    }

    function showMedia(dataUrl, meta = {}) {
      const cleanUrl = String(dataUrl || "").trim();
      const m = SAFE_MEDIA_DATA_URL_RE.exec(cleanUrl);
      if (!m) {
        show("error", "⚠ Invalid or unsupported encrypted media format.", null);
        return;
      }
      const fullMime = m[1].toLowerCase();
      const isVideo = fullMime.startsWith("video/");
      const isAudio = fullMime.startsWith("audio/");

      revealed = true;
      setCollapsed(false);
      bubble.replaceChildren();

      const headerLabel = isVideo
        ? "🎬 VeilX Video"
        : isAudio
        ? "🎙 VeilX Voice Note"
        : "🔓 VeilX Image";
      const statusRow = make("div", "status ok", headerLabel);
      if (meta.badge) statusRow.appendChild(make("span", "pq-pill", meta.badge));
      if (meta.chunkLabel) statusRow.appendChild(make("span", "pq-pill", meta.chunkLabel));
      bubble.appendChild(statusRow);

      if (isVideo) {
        const wrap = make("div", "vx-video-wrap");
        const video = document.createElement("video");
        video.className = "vx-video";
        video.controls = true;
        video.playsInline = true;
        video.preload = "metadata";
        video.src = cleanUrl;
        wrap.appendChild(video);
        bubble.appendChild(wrap);
      } else if (isAudio) {
        const wrap = make("div", "vx-audio-wrap");
        const audio = document.createElement("audio");
        audio.className = "vx-audio";
        audio.controls = true;
        audio.preload = "metadata";
        audio.src = cleanUrl;
        wrap.appendChild(audio);
        bubble.appendChild(wrap);
      } else {
        const wrap = make("div", "vx-img-wrap");
        const img = document.createElement("img");
        img.className = "vx-img";
        img.alt = "Decrypted VeilX image";
        img.src = cleanUrl;
        img.title = "Click to toggle full-resolution zoom";
        img.addEventListener("click", () => wrap.classList.toggle("expanded"));
        wrap.appendChild(img);
        bubble.appendChild(wrap);
      }

      const actions = make("div", "vx-img-actions");
      const subType = fullMime.split("/")[1] || "bin";
      const extMap = { jpeg: "jpg", quicktime: "mov", mpeg: "mp3", "x-m4a": "m4a" };
      const ext = extMap[subType] || subType;
      const dlLabel = isVideo ? "⬇ Save Video" : isAudio ? "⬇ Save Voice" : "⬇ Save Original";
      const dl = make("a", "vx-img-dl", dlLabel);
      dl.href = cleanUrl;
      dl.download = `veilx-encrypted-${isVideo ? "video" : isAudio ? "voice" : "image"}.${ext}`;
      actions.appendChild(dl);

      const commaIdx = cleanUrl.indexOf(",");
      const b64Len = commaIdx >= 0 ? cleanUrl.length - commaIdx - 1 : cleanUrl.length;
      const kb = Math.max(0.1, Math.round(((b64Len * 3) / 4 / 1024) * 10) / 10);
      const sizeStr = kb >= 1024 ? `${(kb / 1024).toFixed(2)} MB` : `${kb} KB`;
      actions.appendChild(make("span", "vx-img-meta", sizeStr));
      bubble.appendChild(actions);
    }

    const controller = {
      isConnected: () => host.isConnected,
      isRevealed: () => revealed,
      isCollapsed: () => collapsed,
      setCollapsed,
      showProgress,
      showMedia,
      showImage: showMedia,
      showRevealed,
      retry: () => attempt(),
    };

    async function attempt() {
      if (revealed || busy) return;
      busy = true;
      show("", "Decrypting…");
      try {
        const result = await decryptFn(blob, controller);
        if (result.ok) {
          if (result.handledByGroup) {
            revealed = true;
          } else if (result.isImage || result.isMedia) {
            showMedia(result.text, { badge: result.badge, chunkLabel: result.chunkLabel });
          } else {
            showRevealed(result.text, { badge: result.badge, chunkLabel: result.chunkLabel });
          }
        } else {
          const f = FAILURE_TEXT[result.reason] || FAILURE_TEXT.bad;
          show(f[0], f[1], f[2]);
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

    return controller;
  }

  // ── 2. Key-Exchange Message Label ────────────────────────────────────────

  function renderKeyLabel(original, partLabel) {
    const { host, shadow } = createHost();
    const bubble = make("div", "bubble");
    const statusRow = make("div", "status ok", "🔑 VeilX key exchange message" + (partLabel ? ` (${partLabel})` : ""));
    statusRow.appendChild(make("span", "pq-pill", "ML-KEM-768 + P-256"));
    bubble.appendChild(statusRow);
    shadow.appendChild(bubble);
    replaceElement(original, host);
  }

  // ── 3. VeilX Cross-Origin Extension Iframe Composer ──────────────────────

  function renderComposer(anchorEl) {
    const { host, shadow } = createHost("div", COMPOSER_HOST_ATTRIBUTE);

    const SHIELDED_EVENTS = [
      "keydown", "keyup", "keypress", "beforeinput", "input",
      "compositionstart", "compositionupdate", "compositionend", "paste", "copy", "cut",
    ];
    for (const evtName of SHIELDED_EVENTS) {
      window.addEventListener(
        evtName,
        (e) => { if (e.target === host) e.stopImmediatePropagation(); },
        true
      );
    }

    const wrap = make("div", "vx-iframe-wrap");
    const iframeEl = document.createElement("iframe");
    iframeEl.className = "vx-composer-iframe";
    const srcFor = (tid) => chrome.runtime.getURL("composer/composer.html") + `?threadId=${encodeURIComponent(tid || "")}`;
    iframeEl.src = srcFor(VX.dom.getThreadId());
    iframeEl.setAttribute("title", "VeilX Secure Composer");
    iframeEl.setAttribute("allow", "microphone");
    wrap.appendChild(iframeEl);
    shadow.appendChild(wrap);

    anchorEl.insertAdjacentElement("afterend", host);

    function updateState({ enabled, threadId }) {
      if (threadId) {
        const expected = srcFor(threadId);
        if (iframeEl.src !== expected) iframeEl.src = expected;
      }
      host.hidden = !enabled;
    }

    return {
      host,
      isConnected: () => host.isConnected,
      isMounted: () => host.isConnected && Boolean(iframeEl.isConnected),
      updateState,
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

if (typeof module !== "undefined") module.exports = VX.ui;
