/**
 * src/content.js — VeilX 1.0.0 page script (runs on instagram.com).
 *
 * Responsibilities: find VeilX messages in the chat, decrypt/render them
 * (including Zero-Knowledge Relay 1-DM original-fidelity images, short videos,
 * voice notes, and multi-chunk fallback images), run the key-exchange state
 * machine via VX.session, and relay ciphertext (never plaintext) from the
 * extension-origin composer into Instagram's send box.
 *
 * Fail-closed: if the VeilX composer is not mounted, or if someone types into
 * Instagram's own message box, nothing is encrypted-from-or-sent-through that
 * box — the attempt is blocked and the user is told why.
 */

(function () {
  "use strict";

  const P = VX.protocol;
  const C = VX.crypto;
  const { store, dom, ui, util, session } = VX;

  const MAX_DECRYPTS_PER_SCAN = 120;
  const ALLOWED_SIDECAR_MIME_RE =
    /^(image\/(webp|png|jpeg|jpg|gif)|video\/(mp4|webm|quicktime)|audio\/(webm|ogg|mp4|mpeg|mp3|wav|x-m4a))$/i;

  let settings = {
    enabled: true, autoDecrypt: true, beautifyUi: true, padMessages: true, requireVerification: true,
  };

  let sending = false;
  let activeComposer = null;
  let activeAnchorInput = null;
  let lastThreadId = null;
  const pendingBubbles = new Set();
  const incomingOffers = new Map(); // threadId -> { entry, replaces }
  const imageGroups = new Map();    // "${threadId}:${gid}" -> { ct, badge, parts: Map<ci, string>, controllers: Map<ci, controller> }
  const sidecarCache = new Map();   // blobUrl -> decrypted Data URL (prevents re-downloading on virtual scroller re-renders)

  // ── Posting into Instagram's box (ciphertext / key packets only) ─────────

  function submitMessage(input) {
    if (!dom.clickSendButton()) dom.pressEnter(input);
  }

  async function postToChat(texts, isValid, fast = false) {
    for (const t of texts) {
      if (typeof t !== "string" || t.length > util.MAX_MESSAGE_CHARS || !isValid(t)) {
        throw new Error("Refusing to post: not a VeilX ciphertext.");
      }
    }
    const input = dom.findMessageInput();
    if (!input) throw new Error("Open a chat first.");
    if (dom.readInputText(input)) throw new Error("Clear Instagram's message box before sending securely.");

    sending = true;
    try {
      const interDelay = fast ? 45 : 90;
      const finalDelay = fast ? 35 : 70;
      for (let i = 0; i < texts.length; i++) {
        const ready = await dom.writeInputText(input, texts[i]);
        if (!ready || dom.readInputText(input) !== texts[i]) {
          await dom.writeInputText(input, "");
          throw new Error("Could not safely prepare the encrypted message. Nothing was sent.");
        }
        submitMessage(input);
        await dom.wait(i < texts.length - 1 ? interDelay : finalDelay);
        if (dom.readInputText(input) === texts[i]) {
          throw new Error("Instagram did not send the message. It remains in the message box.");
        }
      }
      return { ok: true };
    } finally {
      sending = false;
    }
  }

  const isBlob = (t) => Boolean(P.parseMessage(t));
  const isKeyPacket = (t) => Boolean(P.parseKeyPacket(t));

  async function sendCiphertext(blobOrBlobs, requestedThreadId, fast = false) {
    if (requestedThreadId && dom.getThreadId() && requestedThreadId !== dom.getThreadId()) {
      throw new Error("The open chat changed. Try again.");
    }
    const list = Array.isArray(blobOrBlobs) ? blobOrBlobs : [blobOrBlobs];
    return postToChat(list, isBlob, Boolean(fast || list.length > 1));
  }

  // ── Key exchange actions ─────────────────────────────────────────────────

  async function startExchange() {
    const threadId = dom.getThreadId();
    if (!threadId) throw new Error("Open a chat first.");
    const { packets } = await session.createOffer(threadId);
    await postToChat(packets, isKeyPacket);
    return { ok: true };
  }

  async function acceptIncoming() {
    const threadId = dom.getThreadId();
    const pending = threadId && incomingOffers.get(threadId);
    if (!pending) throw new Error("There is no key offer from your contact to accept.");
    const { packets } = await session.acceptOffer(threadId, pending.entry);
    incomingOffers.delete(threadId);
    await postToChat(packets, isKeyPacket);
    return { ok: true };
  }

  function offerToast(threadId, replaces) {
    ui.showToast(
      replaces
        ? "Your contact started a NEW key exchange. Accept only if they told you they re-installed or changed device."
        : "Your contact started a quantum-safe key exchange.",
      {
        kind: "warning", actionLabel: "Accept", timeoutMs: 0,
        onAction: () => acceptIncoming().then(
          () => ui.showToast("Reply sent. Compare the safety code in the VeilX popup before chatting.", { kind: "info" }),
          (err) => ui.showToast(err.message || "Could not accept.", { kind: "error" })
        ),
      }
    );
  }

  async function handleKeyEntries(threadId, entries) {
    const events = await session.processKeyEntries(threadId, entries);
    for (const ev of events) {
      if (ev.type === "established") {
        ui.showToast("Key exchange complete. Open the VeilX popup and compare the safety code with your contact.", { kind: "info", timeoutMs: 12000 });
      } else if (ev.type === "auto-accepted") {
        postToChat(ev.packets, isKeyPacket).catch((err) => ui.showToast(err.message, { kind: "error" }));
        ui.showToast("Both of you started at once; completing the exchange. Compare the safety code in the popup.", { kind: "info" });
      } else if (ev.type === "offer-received") {
        const prev = incomingOffers.get(threadId);
        incomingOffers.set(threadId, { entry: ev.entry, replaces: ev.replacesSession });
        if (!prev || prev.entry.id !== ev.entry.id) offerToast(threadId, ev.replacesSession);
      }
    }
    if (events.length) await syncComposerState();
  }

  // ── Zero-Knowledge Relay Sidecar Download & Decryption ───────────────────

  function askBackgroundDownload(url) {
    return new Promise((resolve) => {
      if (typeof chrome === "undefined" || !chrome.runtime || typeof chrome.runtime.sendMessage !== "function") {
        resolve(null);
        return;
      }
      try {
        const maybe = chrome.runtime.sendMessage({ type: "VX_RELAY_DOWNLOAD", url }, (reply) => resolve(reply || null));
        if (maybe && typeof maybe.then === "function") {
          maybe.then((res) => resolve(res || null), () => resolve(null));
        }
      } catch (_) {
        resolve(null);
      }
    });
  }

  async function fetchAndDecryptSidecar(sidecar, onProgress) {
    if (!sidecar || typeof sidecar.u !== "string" || !sidecar.k || !sidecar.h) {
      throw new Error("Malformed sidecar media pointer.");
    }
    if (sidecarCache.has(sidecar.u)) {
      return sidecarCache.get(sidecar.u);
    }

    if (typeof onProgress === "function") onProgress(25, "Downloading encrypted media from Relay (25%)…");
    let envelopeBytes = null;
    if (typeof window.vxRelayFetch === "function") {
      const resp = await window.vxRelayFetch(sidecar.u, { method: "GET" });
      if (!resp || !resp.ok) {
        throw new Error(`Encrypted media blob expired or unavailable (HTTP ${resp ? resp.status : "error"}).`);
      }
      envelopeBytes = new Uint8Array(await resp.arrayBuffer());
    } else {
      if (typeof globalThis.fetch === "function") {
        try {
          const resp = await globalThis.fetch(sidecar.u, { method: "GET" });
          if (resp && resp.ok) {
            envelopeBytes = new Uint8Array(await resp.arrayBuffer());
          }
        } catch (_) {}
      }
      if (!envelopeBytes) {
        const swRes = await askBackgroundDownload(sidecar.u);
        if (swRes && swRes.ok && swRes.bodyB64) {
          envelopeBytes = C.base64ToBytes(swRes.bodyB64);
        } else {
          throw new Error((swRes && swRes.error) || "Encrypted media blob expired or unavailable.");
        }
      }
    }

    if (typeof onProgress === "function") onProgress(75, "Verifying SHA-256 & decrypting AES-256-GCM (75%)…");
    const rawMt = String(sidecar.mt || "image/webp").split(";")[0].trim().toLowerCase();
    const mimeType = ALLOWED_SIDECAR_MIME_RE.test(rawMt) ? rawMt : "image/webp";
    const plainBytes = await C.openMediaBinary(envelopeBytes, sidecar.k, sidecar.h, mimeType);
    if (typeof onProgress === "function") onProgress(95, "Rendering decrypted media (95%)…");
    const dataUrl = `data:${mimeType};base64,${C.bytesToBase64(plainBytes)}`;
    sidecarCache.set(sidecar.u, dataUrl);
    return dataUrl;
  }

  // ── Multi-Message In-Band Image Reassembly & Decryption ──────────────────

  function renderImageGroup(group) {
    let anchorCi = -1;
    for (const [ci, ctrl] of group.controllers.entries()) {
      if (!ctrl || !ctrl.isConnected()) {
        group.controllers.delete(ci);
        continue;
      }
      if (ci > anchorCi) anchorCi = ci;
    }
    if (anchorCi < 0) return;

    for (const [ci, ctrl] of group.controllers.entries()) {
      if (ci !== anchorCi) {
        ctrl.setCollapsed(true);
      }
    }

    const anchorCtrl = group.controllers.get(anchorCi);
    if (!anchorCtrl) return;

    let complete = group.parts.size >= group.ct;
    let assembled = "";
    if (complete) {
      for (let i = 1; i <= group.ct; i++) {
        const part = group.parts.get(i);
        if (typeof part !== "string") {
          complete = false;
          break;
        }
        assembled += part;
      }
    }

    if (complete && assembled.startsWith("data:image/")) {
      anchorCtrl.showMedia(assembled, {
        badge: group.badge,
        chunkLabel: `In-Band · ${group.ct} parts`,
      });
    } else {
      anchorCtrl.showProgress(
        `Reassembling encrypted image (${group.parts.size}/${group.ct} parts)…`,
        { badge: group.badge }
      );
    }
  }

  async function decryptForThread(threadId, blob, controller) {
    if (!threadId) return { ok: false, reason: "no-key" };
    const r = await session.decryptBlob(threadId, blob);
    if (!r.ok) return r;
    const m = r.meta || {};
    let badge;
    if (m.mode === "passphrase") badge = "Passphrase · no forward secrecy";
    else badge = m.verified ? "PQ · forward-secret" : "PQ · unverified key";

    // Option B: 1-DM Zero-Knowledge Sidecar Media Pointer (Images, Short Videos, Voice Notes)
    if (m.m === "sidecar" && m.sidecar && m.sidecar.u) {
      if (controller) {
        controller.showProgress("🔓 Downloading encrypted media (15%)…", { badge, percent: 15 });
      }
      const dataUrl = await fetchAndDecryptSidecar(m.sidecar, (pct, msg) => {
        if (controller) controller.showProgress(`🔓 ${msg}`, { badge, percent: pct });
      });
      return {
        ok: true,
        text: dataUrl,
        badge,
        isImage: true,
        isMedia: true,
        chunkLabel: "R2 Relay · 1 DM",
      };
    }

    const isImgPayload =
      m.m === "img" ||
      ((!m.ci || m.ci === 1) && typeof r.text === "string" && r.text.startsWith("data:image/"));

    if (m.gid && m.ct > 1 && (isImgPayload || imageGroups.has(`${threadId}:${m.gid}`))) {
      const gKey = `${threadId}:${m.gid}`;
      let group = imageGroups.get(gKey);
      if (!group) {
        group = { ct: m.ct, badge, parts: new Map(), controllers: new Map() };
        imageGroups.set(gKey, group);
      }
      group.ct = m.ct;
      group.badge = badge;
      group.parts.set(m.ci, r.text);
      if (controller) group.controllers.set(m.ci, controller);

      if (group.parts.size < group.ct && typeof session.getGroupChunks === "function") {
        const stored = await session.getGroupChunks(threadId, m.gid);
        if (stored && stored.parts) {
          for (const [k, v] of Object.entries(stored.parts)) {
            const idx = Number(k);
            if (!group.parts.has(idx)) group.parts.set(idx, v);
          }
        }
      }

      renderImageGroup(group);
      return { ok: true, text: r.text, badge, handledByGroup: true };
    }

    if ((!m.ct || m.ct === 1) && isImgPayload) {
      return {
        ok: true,
        text: r.text,
        badge,
        isImage: true,
        isMedia: true,
        chunkLabel: "In-Band · 1 part",
      };
    }

    return {
      ok: true,
      text: r.text,
      badge,
      chunkLabel: m.ct && m.ct > 1 ? `${m.ci}/${m.ct}` : undefined,
    };
  }

  // ── Fail-closed guard for Instagram's own message box ────────────────────

  function attachNativeGuards() {
    const warn = () =>
      ui.showToast(
        "Blocked: typing in Instagram's own box is not private. Use the VeilX composer, or switch VeilX off in the popup.",
        { kind: "warning" }
      );

    function shouldBlock() {
      if (!settings.enabled || !dom.isDmPage()) return false;
      const input = dom.findMessageInput();
      if (!input) return false;
      const text = dom.readInputText(input);
      if (!text) return false;
      if (sending && (isBlob(text) || isKeyPacket(text))) return false;
      return true;
    }

    document.addEventListener("keydown", (e) => {
      if (e._veilxSynthetic) return;
      if (e.key !== "Enter" || e.shiftKey || e.isComposing || e.keyCode === 229) return;
      const input = dom.findMessageInput();
      if (!input || (e.target !== input && !input.contains(e.target))) return;
      if (!shouldBlock()) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      warn();
    }, true);

    document.addEventListener("click", (e) => {
      if (!dom.closestSendButton(e.target)) return;
      if (!shouldBlock()) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      warn();
    }, true);
  }

  // ── Composer mounting ────────────────────────────────────────────────────

  async function syncComposerState() {
    const input = dom.findMessageInput();
    const mounted = Boolean(activeComposer && activeComposer.isMounted());
    if (input) dom.setNativeComposerHidden(input, Boolean(settings.enabled && mounted));
    if (activeComposer) activeComposer.updateState({ enabled: settings.enabled, threadId: dom.getThreadId() });
  }

  async function ensureOnPageComposer() {
    if (!dom.isDmPage()) {
      if (activeComposer) { activeComposer.remove(); activeComposer = null; activeAnchorInput = null; }
      return;
    }
    const input = dom.findMessageInput();
    if (!input) return;

    const currentThreadId = dom.getThreadId();
    if (activeComposer && activeComposer.isConnected() && activeAnchorInput === input) {
      if (lastThreadId !== currentThreadId) {
        lastThreadId = currentThreadId;
        await syncComposerState();
      }
      return;
    }
    if (activeComposer) { activeComposer.remove(); activeComposer = null; }

    const anchorEl = dom.findComposerContainer(input) || input;
    activeAnchorInput = input;
    lastThreadId = currentThreadId;
    activeComposer = ui.renderComposer(anchorEl);
    await syncComposerState();
  }

  // ── Scanning ─────────────────────────────────────────────────────────────

  let scanTimer = null;
  let scanning = false;
  let scanAgain = false;

  function scheduleScan() {
    if (!dom.isDmPage()) return;
    clearTimeout(scanTimer);
    scanTimer = setTimeout(runScan, 120);
  }

  async function runScan() {
    if (scanning) { scanAgain = true; return; }
    scanning = true;
    try {
      await ensureOnPageComposer();
      await scanMessages();
    } catch (err) {
      console.error("[VeilX] scan error:", err);
    } finally {
      scanning = false;
      if (scanAgain) { scanAgain = false; scheduleScan(); }
    }
  }

  async function scanMessages() {
    if (!dom.isDmPage()) return;
    const input = dom.findMessageInput();
    const pane = dom.getConversationPane(input);
    const root = pane || document.body;
    const threadId = dom.getThreadId();

    const found = dom.findEncryptedElements(root, [P.MSG_PREFIX, P.KEY_PREFIX]);
    if (found.length === 0) return;

    const rawKeyTexts = [];
    for (const { el, text, handled } of found) {
      if (!text.startsWith(P.KEY_PREFIX) || !pane) continue;
      const part = P.parseKeyPacket(text);
      if (!part) continue;
      rawKeyTexts.push(text);
      if (!handled) ui.renderKeyLabel(el, `${part.index}/${part.total}`);
    }
    if (threadId && rawKeyTexts.length > 0) {
      const entries = P.reassembleKeyPackets(rawKeyTexts);
      if (entries.length > 0) await handleKeyEntries(threadId, entries);
    }

    let decryptCount = 0;
    for (const { el, text, handled } of found) {
      if (text.startsWith(P.KEY_PREFIX) || handled) continue;
      if (decryptCount >= MAX_DECRYPTS_PER_SCAN) continue;
      const parsed = P.parseMessage(text);
      if (!parsed) continue;
      decryptCount++;
      const controller = ui.renderEncrypted(
        el,
        parsed.blob,
        (b, ctrl) => decryptForThread(threadId, b, ctrl),
        settings.autoDecrypt
      );
      pendingBubbles.add(controller);
    }
  }

  function retryPending() {
    let count = 0;
    for (const controller of pendingBubbles) {
      if (!controller.isConnected()) pendingBubbles.delete(controller);
      else if (!controller.isRevealed() && settings.autoDecrypt && count < MAX_DECRYPTS_PER_SCAN) {
        count++;
        controller.retry();
      }
    }
  }

  // ── IPC from the popup / background broker ───────────────────────────────

  const HANDLED_TYPES = new Set([
    "VX_QUERY", "VX_START_EXCHANGE", "VX_ACCEPT_OFFER", "VX_SEND_CIPHERTEXT",
    "VX_BROKER_SEND_CIPHERTEXT", "VX_BROKER_START_EXCHANGE", "VX_BROKER_ACCEPT_OFFER", "VX_BROKER_QUERY",
  ]);

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;
    if (!message || !HANDLED_TYPES.has(message.type)) return;
    if (!dom.isDmPage()) return false;

    let work;
    if (message.type.endsWith("QUERY")) {
      const tid = dom.getThreadId();
      const off = tid && incomingOffers.get(tid);
      work = Promise.resolve({ ok: true, threadId: tid, offer: off ? { replaces: off.replaces } : null });
    } else if (message.type.endsWith("SEND_CIPHERTEXT")) {
      work = sendCiphertext(message.ciphertext, message.threadId, Boolean(message.fast));
    } else if (message.type.endsWith("START_EXCHANGE")) {
      work = startExchange();
    } else {
      work = acceptIncoming();
    }
    work.then(sendResponse).catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  });

  chrome.storage.onChanged.addListener((changes) => {
    let stateChanged = false;
    for (const name of Object.keys(changes)) {
      const nv = changes[name].newValue;
      if (name === "enabled") settings.enabled = nv !== false;
      else if (name === "autoDecrypt") settings.autoDecrypt = nv !== false;
      else if (name === "beautifyUi") { settings.beautifyUi = nv !== false; dom.applyPageTheme(settings.beautifyUi); }
      else if (name === "padMessages") settings.padMessages = nv !== false;
      else if (name === "requireVerification") settings.requireVerification = nv !== false;
      if (name === "vaultLocked" || name.startsWith("conv:")) stateChanged = true;
    }
    if (stateChanged || changes.autoDecrypt) retryPending();
    syncComposerState().catch(() => {});
  });

  // ── Start-up ─────────────────────────────────────────────────────────────

  attachNativeGuards();

  async function boot() {
    settings = await store.getSettings();
    dom.applyPageTheme(settings.beautifyUi);
    new MutationObserver(scheduleScan).observe(document.body, { childList: true, subtree: true });
    scheduleScan();
  }

  boot().catch((err) => console.error("[VeilX] start-up failed:", err));
})();
