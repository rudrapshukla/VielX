/**
 * composer/composer.js — extension-origin composer (VeilX 1.1.0).
 *
 * Runs in the chrome-extension:// origin, so Instagram's JavaScript never sees
 * keystrokes or selected media.
 *
 * Original-Fidelity Encrypted Media Architecture (Images, Short Videos, Voice Notes):
 *   • Sidecar Relay Path (Default): Reads the ORIGINAL file bytes (`file.arrayBuffer()`)
 *     directly—WITHOUT resizing or re-encoding through `<canvas>` and WITHOUT unnecessary
 *     base64 conversion—so photos, short videos (`video/mp4`, `video/webm`), and voice notes
 *     (`audio/webm`, `audio/ogg`, `audio/mp4`, `audio/mpeg`, `audio/wav`) preserve 100%
 *     lossless bit-for-bit fidelity up to 15 MB.
 *   • Real-Time Progress Bar & ETA: Displays live percentage, MB uploaded, and estimated
 *     seconds remaining across reading, AES-256-GCM encryption, Proof-of-Work, and XHR upload.
 *   • Voice Note Microphone Permission Bridge: Works directly inside `<iframe allow="microphone">`,
 *     and if Instagram's top-level `Permissions-Policy` header or first-time extension prompt
 *     blocks subframe mic access, automatically opens a compact top-level `chrome-extension://`
 *     Voice Recorder popup that records audio and pipes the raw bytes directly back to the
 *     active Instagram composer bar via `window.opener` / `BroadcastChannel`.
 */

(function () {
  "use strict";

  const { store, util, session, crypto: C } = VX;
  const $ = (id) => document.getElementById(id);

  const SUPPORTED_MEDIA_DATA_URL_RE =
    /^data:((?:image\/(?:webp|png|jpeg|jpg|gif))|(?:video\/(?:mp4|webm|quicktime))|(?:audio\/(?:webm|ogg|mp4|mpeg|mp3|wav|x-m4a)))(?:;codecs=[^;,]+)?;base64,([A-Za-z0-9+/=\s]+)$/i;

  const searchParams = new URLSearchParams(location.search);
  let threadId = searchParams.get("threadId") || null;
  const isVoicePopup = searchParams.get("voicePopup") === "1";
  let pollTimer = null;

  function broker(payload) {
    return new Promise((resolve) => {
      if (typeof chrome === "undefined" || !chrome.runtime || typeof chrome.runtime.sendMessage !== "function") {
        resolve({ ok: false, error: "Extension runtime unavailable." });
        return;
      }
      try {
        const maybe = chrome.runtime.sendMessage(payload, (reply) => resolve(reply || { ok: false }));
        if (maybe && typeof maybe.then === "function") {
          maybe.then((res) => resolve(res || { ok: false }), (err) => resolve({ ok: false, error: err.message }));
        }
      } catch (err) {
        resolve({ ok: false, error: err.message });
      }
    });
  }

  let flashTimer = null;
  let flashUntil = 0;
  let basePlaceholder = "";

  function flash(message, durationMs = 6000) {
    const input = $("composeInput");
    flashUntil = Date.now() + durationMs;
    input.placeholder = message;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => {
      flashUntil = 0;
      input.placeholder = basePlaceholder;
    }, durationMs);
  }

  function formatBytes(bytes) {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  }

  function setMediaProgress(percent, stageText, counterText) {
    const pill = $("composerPill");
    const wrap = $("progressWrap");
    const fill = $("progressFill");
    const input = $("composeInput");
    const counter = $("byteCounter");

    if (percent === null || percent === undefined) {
      if (pill) pill.classList.remove("uploading");
      if (wrap) wrap.hidden = true;
      if (fill) fill.style.width = "0%";
      updateByteCounter();
      return;
    }

    const clamped = Math.max(2, Math.min(100, Math.round(percent)));
    if (pill) pill.classList.add("uploading");
    if (wrap) wrap.hidden = false;
    if (fill) fill.style.width = `${clamped}%`;
    if (stageText && input) input.placeholder = stageText;
    if (counter) {
      counter.textContent = counterText || `${clamped}%`;
      counter.className = "vx-counter active-progress";
    }
  }

  function updateByteCounter() {
    const text = $("composeInput").value;
    const bytes = util.utf8ByteLength(text);
    const chunks = Math.max(1, Math.ceil(bytes / util.MAX_PLAINTEXT_BYTES));
    const counter = $("byteCounter");
    counter.textContent = chunks === 1 ? `${bytes} B` : `${bytes} B · ${chunks}+ parts`;
    counter.className = "vx-counter" + (chunks > 1 || bytes > util.MAX_PLAINTEXT_BYTES - 60 ? " warn" : "");
    const ta = $("composeInput");
    ta.style.height = "auto";
    ta.style.height = Math.min(96, Math.max(22, ta.scrollHeight)) + "px";
  }

  let uiState = "none";
  async function renderState() {
    const settings = await store.getSettings();
    const vault = await store.getVaultStatus();
    const btn = $("statusBtn");
    const label = $("statusLabel");
    const input = $("composeInput");
    const imgBtn = $("imageBtn");
    const voiceBtn = $("voiceBtn");
    const base = (text) => {
      basePlaceholder = text;
      if (Date.now() >= flashUntil && !sending) {
        input.placeholder = text;
      }
    };

    if (isVoicePopup) {
      uiState = "ready";
      btn.className = "vx-badge-btn";
      label.textContent = "🎙 Voice Recorder";
      if (imgBtn) imgBtn.hidden = true;
      if ($("sendBtn")) $("sendBtn").hidden = true;
      if (voiceBtn) voiceBtn.disabled = false;
      base("Click Voice to start/stop recording your encrypted voice note…");
      return;
    }

    if (vault.locked) {
      uiState = "locked";
      btn.className = "vx-badge-btn needs-action";
      label.textContent = "Vault Locked";
      if (imgBtn) imgBtn.disabled = true;
      if (voiceBtn) voiceBtn.disabled = true;
      base("Unlock your Key Vault in the VeilX toolbar icon…");
      return;
    }

    const status = threadId ? await session.getStatus(threadId) : { state: "none" };

    if (status.state === "passphrase") {
      uiState = "ready";
      btn.className = "vx-badge-btn";
      label.textContent = "Passphrase · no FS";
      if (imgBtn) imgBtn.disabled = false;
      if (voiceBtn) voiceBtn.disabled = false;
      base("Message, record voice, or drop photo/video securely with VeilX…");
      return;
    }
    if (status.state === "established") {
      if (settings.requireVerification && !status.verified) {
        uiState = "verify";
        btn.className = "vx-badge-btn needs-action";
        label.textContent = "Verify in popup";
        if (imgBtn) imgBtn.disabled = true;
        if (voiceBtn) voiceBtn.disabled = true;
        base("Compare the safety code in the VeilX popup to unlock sending…");
      } else {
        uiState = "ready";
        btn.className = "vx-badge-btn";
        label.textContent = status.verified ? "PQ · forward-secret" : "PQ · unverified";
        if (imgBtn) imgBtn.disabled = false;
        if (voiceBtn) voiceBtn.disabled = false;
        base("Message, record voice, or drop photo/video securely with VeilX…");
      }
      return;
    }
    if (imgBtn) imgBtn.disabled = true;
    if (voiceBtn) voiceBtn.disabled = true;
    btn.className = "vx-badge-btn needs-action";
    if (status.state === "offered") {
      uiState = "offered";
      label.textContent = "Waiting for contact…";
      base("Your key offer was posted — waiting for your contact to accept…");
    } else {
      const q = await broker({ type: "VX_BROKER_QUERY" });
      if (q && q.ok && q.offer) {
        uiState = "accept";
        label.textContent = "Accept Key";
        base("Your contact sent a key offer — click Accept Key…");
      } else {
        uiState = "none";
        label.textContent = "Exchange Key";
        base("Click Exchange Key (or set a passphrase in the popup)…");
      }
    }
  }

  // ── Lossless Original-Byte Media Reading (Zero Base64 Overhead on Relay) ──

  function normalizeMimeType(rawMime, fileName = "") {
    const lower = String(rawMime || "").split(";")[0].trim().toLowerCase();
    if (lower === "image/jpg") return "image/jpeg";
    if (lower === "audio/mp3") return "audio/mpeg";
    if (lower === "audio/x-m4a") return "audio/mp4";
    if (
      /^(image\/(webp|png|jpeg|gif)|video\/(mp4|webm|quicktime)|audio\/(webm|ogg|mp4|mpeg|wav))$/.test(lower)
    ) {
      return lower;
    }
    const ext = String(fileName || "").split(".").pop().toLowerCase();
    const byExt = {
      webp: "image/webp", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
      mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime",
      ogg: "audio/ogg", m4a: "audio/mp4", mp3: "audio/mpeg", wav: "audio/wav",
    };
    return byExt[ext] || "image/webp";
  }

  function dataUrlToBytesAndMime(dataUrl) {
    const m = SUPPORTED_MEDIA_DATA_URL_RE.exec(String(dataUrl || "").trim());
    if (!m) throw new Error("Unsupported or invalid media data URL.");
    const mimeType = normalizeMimeType(m[1]);
    const bytes = C.base64ToBytes(m[2].replace(/\s+/g, ""));
    return { bytes, mimeType };
  }

  /**
   * Reads the EXACT original bytes of a File/Blob without `<canvas>` resizing
   * and WITHOUT converting to a base64 Data URL unless in-band mode is used.
   */
  async function readOriginalMediaBytes(file) {
    const mimeType = normalizeMimeType(file && file.type, file && file.name);
    if (file && typeof file.arrayBuffer === "function") {
      const buf = await file.arrayBuffer();
      const bytes = new Uint8Array(buf);
      return { bytes, mimeType };
    }
    if (typeof FileReader !== "undefined") {
      const buf = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error("Could not read media file."));
        reader.readAsArrayBuffer(file);
      });
      return { bytes: new Uint8Array(buf), mimeType };
    }
    throw new Error("Unsupported media input.");
  }

  function xhrUploadWithProgress(url, headers, bodyBytes, onProgress) {
    return new Promise((resolve, reject) => {
      if (typeof XMLHttpRequest === "undefined") {
        reject(new Error("XHR unavailable"));
        return;
      }
      const xhr = new XMLHttpRequest();
      const startMs = Date.now();
      xhr.open("POST", url, true);
      for (const [k, v] of Object.entries(headers || {})) {
        xhr.setRequestHeader(k, v);
      }
      if (xhr.upload && typeof onProgress === "function") {
        xhr.upload.onprogress = (evt) => {
          if (evt.lengthComputable && evt.total > 0) {
            const frac = Math.min(1, evt.loaded / evt.total);
            const elapsedSec = Math.max(0.05, (Date.now() - startMs) / 1000);
            const speedBps = evt.loaded / elapsedSec;
            const remainingBytes = Math.max(0, evt.total - evt.loaded);
            const etaSec = speedBps > 0 ? Math.ceil(remainingBytes / speedBps) : 0;
            onProgress({ loaded: evt.loaded, total: evt.total, frac, etaSec });
          }
        };
      }
      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText || "{}");
          if (xhr.status >= 200 && xhr.status < 300 && data && data.ok && data.url) {
            resolve(data);
          } else {
            reject(new Error((data && data.error) || `Relay HTTP ${xhr.status}`));
          }
        } catch (_) {
          reject(new Error(`Relay HTTP ${xhr.status}`));
        }
      };
      xhr.onerror = () => reject(new Error("XHR network error"));
      xhr.send(bodyBytes);
    });
  }

  /**
   * Uploads an encrypted `VX1B` media envelope to the configured Zero-Knowledge Relay
   * while reporting real-time progress and ETA to `setMediaProgress`.
   */
  async function uploadEncryptedMediaToRelay(plainBytes, mimeType, settings, kindLabel) {
    const relayBase = (settings && settings.relayUrl ? settings.relayUrl : store.DEFAULT_RELAY_URL).replace(/\/+$/, "");
    const sizeText = formatBytes(plainBytes.byteLength);

    setMediaProgress(18, `Encrypting ${kindLabel} (${sizeText}) with AES-256-GCM…`, "18% · AES-GCM");
    const sealed = await C.sealMediaBinary(plainBytes, mimeType);

    setMediaProgress(28, `Computing Proof-of-Work for ${kindLabel}…`, "28% · PoW");
    const timestamp = String(Date.now());
    const powNonce =
      typeof C.computeRelayPowAsync === "function"
        ? await C.computeRelayPowAsync(timestamp, sealed.sha256Hex, C.RELAY_POW_BITS, (hashes) => {
            const pct = Math.min(42, 28 + Math.floor((hashes / 24000) * 14));
            setMediaProgress(pct, `Computing Proof-of-Work (${hashes.toLocaleString()} hashes)…`, `${pct}% · PoW`);
          })
        : C.computeRelayPow(timestamp, sealed.sha256Hex);

    const signatureB64 = await C.signRelayUpload({
      timestamp,
      sha256Hex: sealed.sha256Hex,
      powNonce,
      relaySecret: settings && settings.relaySecret,
    });

    const uploadUrl = `${relayBase}/upload`;
    const headers = {
      "Content-Type": "application/octet-stream",
      "X-VeilX-Timestamp": timestamp,
      "X-VeilX-SHA256": sealed.sha256Hex,
      "X-VeilX-PoW": powNonce,
      "X-VeilX-Signature": signatureB64,
    };

    const totalBytes = sealed.envelopeBytes.byteLength;
    setMediaProgress(45, `Uploading encrypted ${kindLabel} (0 / ${formatBytes(totalBytes)})…`, "45% · Upload");

    const customFetch = window.vxRelayFetch;
    if (typeof customFetch === "function") {
      setMediaProgress(75, `Uploading encrypted ${kindLabel} (${formatBytes(totalBytes)})…`, "75% · Upload");
      const resp = await customFetch(uploadUrl, { method: "POST", headers, body: sealed.envelopeBytes });
      if (!resp || !resp.ok) {
        let errText = `Relay HTTP ${resp ? resp.status : "error"}`;
        try {
          const errJson = await resp.json();
          if (errJson && errJson.error) errText = errJson.error;
        } catch (_) {}
        throw new Error(errText);
      }
      const data = await resp.json();
      if (!data || !data.ok || !data.url) throw new Error("Relay did not return a valid blob URL.");
      setMediaProgress(92, `Finalizing 1-DM pointer…`, "92%");
      return { u: data.url, k: sealed.keyB64, h: sealed.sha256B64, mt: sealed.mimeType, sz: sealed.size };
    }

    // 1. Try XHR with live byte-level upload progress first
    try {
      const data = await xhrUploadWithProgress(uploadUrl, headers, sealed.envelopeBytes, ({ loaded, total, frac, etaSec }) => {
        const pct = Math.min(92, Math.round(45 + frac * 47));
        const etaStr = etaSec > 0 ? `~${etaSec}s left` : "almost done";
        setMediaProgress(
          pct,
          `Uploading ${kindLabel}: ${formatBytes(loaded)} / ${formatBytes(total)} (${pct}% · ${etaStr})…`,
          `${pct}% · ${etaStr}`
        );
      });
      return { u: data.url, k: sealed.keyB64, h: sealed.sha256B64, mt: sealed.mimeType, sz: sealed.size };
    } catch (_) {}

    // 2. Fallback to fetch()
    if (typeof globalThis.fetch === "function") {
      try {
        setMediaProgress(68, `Uploading ${kindLabel} (${formatBytes(totalBytes)}) to Relay…`, "68% · Upload");
        const resp = await globalThis.fetch(uploadUrl, { method: "POST", headers, body: sealed.envelopeBytes });
        if (resp && resp.ok) {
          const data = await resp.json();
          if (data && data.ok && data.url) {
            return { u: data.url, k: sealed.keyB64, h: sealed.sha256B64, mt: sealed.mimeType, sz: sealed.size };
          }
        }
      } catch (_) {}
    }

    // 3. Fallback to Service Worker Privileged Upload (`VX_RELAY_UPLOAD`)
    setMediaProgress(72, `Uploading ${kindLabel} (${formatBytes(totalBytes)}) via background worker…`, "72% · Upload");
    const swRes = await broker({
      type: "VX_RELAY_UPLOAD",
      url: uploadUrl,
      headers,
      bodyB64: C.bytesToBase64(sealed.envelopeBytes),
    });
    if (swRes && swRes.ok && swRes.data && swRes.data.url) {
      return {
        u: swRes.data.url,
        k: sealed.keyB64,
        h: sealed.sha256B64,
        mt: sealed.mimeType,
        sz: sealed.size,
      };
    }

    throw new Error((swRes && swRes.error) || `Could not reach relay (${relayBase}). Make sure worker.js is deployed.`);
  }

  let sending = false;

  function setControlsDisabled(disabled) {
    $("sendBtn").disabled = disabled;
    if ($("imageBtn")) $("imageBtn").disabled = disabled || uiState !== "ready";
    if ($("voiceBtn") && !activeRecorder) $("voiceBtn").disabled = disabled || uiState !== "ready";
  }

  /**
   * Encrypts and sends raw media bytes (`{ bytes, mimeType, dataUrl }`) or a Data URL.
   * Preserves original file bytes bit-for-bit on the Sidecar Relay path.
   */
  async function encryptAndSendMediaBytes({ bytes, mimeType, dataUrl }, options = {}) {
    if (sending || !threadId) return { ok: false, error: "Busy or no active chat." };
    if (uiState !== "ready") {
      const msg = uiState === "verify" ? "Verify the safety code in the popup first." : "No usable key yet.";
      flash(msg);
      return { ok: false, error: msg };
    }
    const settings = await store.getSettings();
    if (!settings.enabled) return { ok: false, error: "VeilX is disabled." };

    sending = true;
    setControlsDisabled(true);

    try {
      if (options.forceInBand) {
        const rawUrl = dataUrl || `data:${mimeType};base64,${C.bytesToBase64(bytes)}`;
        const blobs = await session.encryptImage(threadId, rawUrl);
        for (let i = 0; i < blobs.length; i++) {
          const pct = Math.round(((i + 1) / blobs.length) * 100);
          setMediaProgress(
            pct,
            `Sending in-band media (${i + 1}/${blobs.length} messages · ${pct}%)…`,
            `${i + 1}/${blobs.length} · ${pct}%`
          );
          const res = await broker({
            type: "VX_BROKER_SEND_CIPHERTEXT",
            ciphertext: blobs[i],
            fast: blobs.length > 1,
            threadId,
          });
          if (!res || !res.ok) throw new Error((res && res.error) || "Could not send encrypted media chunk.");
        }
        setMediaProgress(null);
        flash(`Sent compressed in-band image (${blobs.length} parts).`);
        return { ok: true, mode: "inband", parts: blobs.length };
      }

      const kindLabel = mimeType.startsWith("video/")
        ? "video"
        : mimeType.startsWith("audio/")
        ? "voice note"
        : "original-quality image";

      setMediaProgress(10, `Preparing ${kindLabel} (${formatBytes(bytes.byteLength)})…`, "10%");
      const sidecar = await uploadEncryptedMediaToRelay(bytes, mimeType, settings, kindLabel);

      setMediaProgress(95, `Sending 1 encrypted DM pointer to Instagram…`, "95% · 1 DM");
      const blobs = await session.encryptMediaSidecar(threadId, sidecar);
      for (const blob of blobs) {
        const res = await broker({
          type: "VX_BROKER_SEND_CIPHERTEXT",
          ciphertext: blob,
          threadId,
        });
        if (!res || !res.ok) throw new Error((res && res.error) || "Could not send sidecar pointer.");
      }
      setMediaProgress(100, `✓ Sent encrypted ${kindLabel} (100%)`, "100% · Sent");
      flash(`✓ Sent encrypted ${kindLabel} via Relay (1 message).`);
      return { ok: true, mode: "sidecar", parts: blobs.length, url: sidecar.u, mimeType };
    } catch (err) {
      flash(`Media error: ${err.message || "Upload failed"}`, 8000);
      return { ok: false, error: err.message };
    } finally {
      sending = false;
      setControlsDisabled(false);
      setMediaProgress(null);
      renderState().catch(() => {});
    }
  }

  async function encryptAndSendMediaDataUrl(dataUrl, options = {}) {
    const parsed = dataUrlToBytesAndMime(dataUrl);
    return encryptAndSendMediaBytes({ ...parsed, dataUrl }, options);
  }

  async function handleMediaFile(file) {
    if (!file || sending) return;
    if (!threadId) {
      flash("Open a chat first.");
      return;
    }
    if (uiState !== "ready") {
      flash(uiState === "verify" ? "Verify the safety code in the popup first." : "No usable key yet.");
      return;
    }
    try {
      setMediaProgress(5, `Reading original file (${formatBytes(file.size || 0)})…`, "5% · Read");
      const media = await readOriginalMediaBytes(file);
      return await encryptAndSendMediaBytes(media, { requireSidecar: true });
    } catch (err) {
      setMediaProgress(null);
      flash(err.message || "Could not process media file.");
      return { ok: false, error: err.message };
    }
  }

  // ── Live Encrypted Voice Note Recorder (`🎙 Voice`) + Permission Bridge ───

  let activeRecorder = null;
  let activeStream = null;
  let recordedChunks = [];
  let recordStartMs = 0;
  let recordTimer = null;
  let voiceChannel = null;

  if (typeof BroadcastChannel !== "undefined" && threadId) {
    try {
      voiceChannel = new BroadcastChannel(`veilx_voice_${threadId}`);
      if (!isVoicePopup) {
        voiceChannel.onmessage = (ev) => {
          if (ev && ev.data && ev.data.bytes && ev.data.mimeType) {
            encryptAndSendMediaBytes({
              bytes: new Uint8Array(ev.data.bytes),
              mimeType: ev.data.mimeType,
            });
          }
        };
      }
    } catch (_) {}
  }

  window.vxReceiveRecordedVoice = function (bytes, mimeType) {
    encryptAndSendMediaBytes({ bytes: new Uint8Array(bytes), mimeType });
  };

  function stopVoiceTracks() {
    clearInterval(recordTimer);
    recordTimer = null;
    if (activeStream && typeof activeStream.getTracks === "function") {
      for (const track of activeStream.getTracks()) {
        try { track.stop(); } catch (_) {}
      }
    }
    activeStream = null;
    activeRecorder = null;
    const voiceBtn = $("voiceBtn");
    const voiceLabel = $("voiceLabel");
    if (voiceBtn) voiceBtn.classList.remove("recording");
    if (voiceLabel) voiceLabel.textContent = "Voice";
  }

  function openTopLevelVoicePopup() {
    const popupUrl =
      (typeof chrome !== "undefined" && chrome.runtime && typeof chrome.runtime.getURL === "function"
        ? chrome.runtime.getURL("composer/composer.html")
        : "composer.html") +
      `?threadId=${encodeURIComponent(threadId || "")}&voicePopup=1`;
    const w = window.open(
      popupUrl,
      "VeilXVoiceRecorder",
      "popup=yes,width=520,height=110,menubar=no,toolbar=no,location=no,status=no"
    );
    if (w) {
      flash("Opened VeilX Voice Recorder window (bypasses Instagram iframe mic restriction)…", 7000);
    } else {
      flash("Allow popups or click Media to attach an audio file.", 7000);
    }
  }

  async function toggleVoiceRecording() {
    if (sending) return;
    if (!threadId) {
      flash("Open a chat first.");
      return;
    }
    if (uiState !== "ready") {
      flash(uiState === "verify" ? "Verify the safety code in the popup first." : "Exchange keys first to send voice notes.");
      return;
    }

    // If currently recording -> stop & send!
    if (activeRecorder && activeRecorder.state === "recording") {
      activeRecorder.stop();
      return;
    }

    if (
      typeof navigator === "undefined" ||
      !navigator.mediaDevices ||
      typeof navigator.mediaDevices.getUserMedia !== "function" ||
      typeof MediaRecorder === "undefined"
    ) {
      if (!isVoicePopup && window.self !== window.top) {
        openTopLevelVoicePopup();
        return;
      }
      flash("Microphone unavailable in this context — click Media to attach an audio file.");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      activeStream = stream;
      recordedChunks = [];

      const candidates = [
        "audio/webm;codecs=opus",
        "audio/webm",
        "audio/ogg;codecs=opus",
        "audio/mp4",
      ];
      let chosenMime = "audio/webm";
      if (typeof MediaRecorder.isTypeSupported === "function") {
        for (const c of candidates) {
          if (MediaRecorder.isTypeSupported(c)) {
            chosenMime = c;
            break;
          }
        }
      }

      const recorder = new MediaRecorder(stream, { mimeType: chosenMime, audioBitsPerSecond: 32000 });
      activeRecorder = recorder;
      recordStartMs = Date.now();

      recorder.addEventListener("dataavailable", (e) => {
        if (e.data && e.data.size > 0) recordedChunks.push(e.data);
      });

      recorder.addEventListener("stop", async () => {
        const cleanMime = normalizeMimeType(recorder.mimeType || chosenMime);
        const chunks = recordedChunks.slice();
        stopVoiceTracks();
        if (!chunks.length) return;
        const blob = new Blob(chunks, { type: cleanMime });

        if (isVoicePopup) {
          const buf = await blob.arrayBuffer();
          const u8 = new Uint8Array(buf);
          if (window.opener && typeof window.opener.vxReceiveRecordedVoice === "function") {
            window.opener.vxReceiveRecordedVoice(u8, cleanMime);
            setTimeout(() => window.close(), 250);
            return;
          }
          if (voiceChannel) {
            voiceChannel.postMessage({ bytes: u8, mimeType: cleanMime });
            setTimeout(() => window.close(), 250);
            return;
          }
        }
        await handleMediaFile(blob);
      });

      recorder.start(200);
      const voiceBtn = $("voiceBtn");
      const voiceLabel = $("voiceLabel");
      if (voiceBtn) voiceBtn.classList.add("recording");
      if (voiceLabel) voiceLabel.textContent = "0:00 · Send";
      $("composeInput").placeholder = "🔴 Recording encrypted voice note… click Voice again to send (max 60s)";

      recordTimer = setInterval(() => {
        const elapsedSec = Math.floor((Date.now() - recordStartMs) / 1000);
        const mins = Math.floor(elapsedSec / 60);
        const secs = String(elapsedSec % 60).padStart(2, "0");
        if (voiceLabel) voiceLabel.textContent = `${mins}:${secs} · Send`;
        if (elapsedSec >= 60 && activeRecorder && activeRecorder.state === "recording") {
          activeRecorder.stop();
        }
      }, 250);
    } catch (err) {
      stopVoiceTracks();
      // If Instagram's top-level Permissions-Policy header blocks microphone in the subframe,
      // automatically open the top-level chrome-extension:// Voice Recorder window!
      if (!isVoicePopup && window.self !== window.top) {
        openTopLevelVoicePopup();
        return;
      }
      flash(`Microphone access blocked (${(err && err.message) || "allow microphone in site settings"}).`);
    }
  }

  async function handleSend() {
    if (sending || !threadId) return;
    const input = $("composeInput");
    const raw = input.value;
    if (!raw || !raw.trim()) return;

    if (uiState !== "ready") {
      flash(uiState === "verify" ? "Verify the safety code in the popup first." : "No usable key — click the badge on the left.");
      return;
    }

    const settings = await store.getSettings();
    if (!settings.enabled) {
      flash("VeilX is turned off in the popup.");
      return;
    }

    sending = true;
    setControlsDisabled(true);
    try {
      const blobs = await session.encryptText(threadId, raw);
      for (let i = 0; i < blobs.length; i++) {
        const res = await broker({
          type: "VX_BROKER_SEND_CIPHERTEXT",
          ciphertext: blobs[i],
          fast: blobs.length > 1,
          threadId,
        });
        if (!res || !res.ok) {
          throw new Error((res && res.error) || "Instagram composer not found.");
        }
      }
      input.value = "";
      updateByteCounter();
    } catch (err) {
      flash(`Not sent: ${err.message || "encryption failed"}`);
    } finally {
      sending = false;
      setControlsDisabled(false);
      input.focus();
      renderState().catch(() => {});
    }
  }

  async function handleBadgeClick() {
    if (isVoicePopup) {
      toggleVoiceRecording();
      return;
    }
    if (!threadId) return;
    if (uiState === "none") {
      $("statusLabel").textContent = "Starting…";
      const r = await broker({ type: "VX_BROKER_START_EXCHANGE" });
      if (!r || !r.ok) flash((r && r.error) || "Could not start key exchange.");
      await renderState();
    } else if (uiState === "accept") {
      $("statusLabel").textContent = "Accepting…";
      const r = await broker({ type: "VX_BROKER_ACCEPT_OFFER" });
      if (!r || !r.ok) flash((r && r.error) || "Could not accept key offer.");
      await renderState();
    } else if (uiState === "verify") {
      flash("Open the VeilX extension icon in the browser toolbar to compare and confirm the safety code.");
    } else if (uiState === "locked") {
      flash("Open the VeilX extension icon in the browser toolbar to unlock your Key Vault.");
    } else {
      await renderState();
    }
  }

  function wireEvents() {
    const shield = (e) => e.stopPropagation();
    for (const evt of ["keydown", "keyup", "keypress", "beforeinput", "input", "paste", "copy", "cut"]) {
      window.addEventListener(evt, shield, false);
    }

    $("composeInput").addEventListener("input", updateByteCounter);
    $("composeInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    });
    $("sendBtn").addEventListener("click", handleSend);
    $("statusBtn").addEventListener("click", handleBadgeClick);

    const voiceBtn = $("voiceBtn");
    if (voiceBtn) {
      voiceBtn.addEventListener("click", toggleVoiceRecording);
    }

    const imgBtn = $("imageBtn");
    const imgInput = $("imageInput");
    if (imgBtn && imgInput) {
      imgBtn.addEventListener("click", () => {
        if (sending || uiState !== "ready") {
          flash(uiState === "verify" ? "Verify the safety code first." : "Exchange keys first to send media.");
          return;
        }
        imgInput.click();
      });
      imgInput.addEventListener("change", () => {
        const file = imgInput.files && imgInput.files[0];
        imgInput.value = "";
        if (file) handleMediaFile(file);
      });
    }

    $("composeInput").addEventListener("paste", (e) => {
      const items = e.clipboardData && e.clipboardData.items;
      if (!items) return;
      for (const item of items) {
        if (
          item.type &&
          (item.type.startsWith("image/") || item.type.startsWith("video/") || item.type.startsWith("audio/"))
        ) {
          const file = item.getAsFile();
          if (file) {
            e.preventDefault();
            handleMediaFile(file);
            return;
          }
        }
      }
    });

    const pill = $("composerPill");
    if (pill) {
      pill.addEventListener("dragover", (e) => {
        e.preventDefault();
        pill.classList.add("drag-over");
      });
      pill.addEventListener("dragleave", () => {
        pill.classList.remove("drag-over");
      });
      pill.addEventListener("drop", (e) => {
        e.preventDefault();
        pill.classList.remove("drag-over");
        const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (file) {
          handleMediaFile(file);
        }
      });
    }

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((message, sender) => {
        if (sender.id !== chrome.runtime.id) return;
        if (message && message.type === "VX_ACTIVE_THREAD_CHANGED") {
          threadId = message.threadId || null;
          renderState();
        }
      });
    }
    chrome.storage.onChanged.addListener(() => renderState());
    if (typeof setInterval === "function") {
      pollTimer = setInterval(() => { if (uiState === "none" || uiState === "accept") renderState().catch(() => {}); }, 3000);
      if (pollTimer && pollTimer.unref) pollTimer.unref();
    }
  }

  window.vxSendImageDataUrl = encryptAndSendMediaDataUrl;
  window.vxSendMediaDataUrl = encryptAndSendMediaDataUrl;
  window.vxSendMediaBytes = (bytes, mimeType, opts) => encryptAndSendMediaBytes({ bytes, mimeType }, opts);
  window.vxHandleImageFile = handleMediaFile;
  window.vxHandleMediaFile = handleMediaFile;

  async function init() {
    wireEvents();
    await renderState();
    if (isVoicePopup) {
      setTimeout(() => toggleVoiceRecording(), 120);
    }
  }

  init().catch((err) => console.error("[VeilX] composer init failed:", err));
})();
