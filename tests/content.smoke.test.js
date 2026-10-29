/**
 * tests/content.smoke.test.js — the REAL extension files inside a simulated
 * Instagram page, with composer/composer.html in a separate extension-origin iframe.
 *
 * Verifies:
 *   1. The composer is the extension iframe only: no text field exists in the page,
 *      and typing/sending leaks no keyboard events or window messages to Instagram.
 *   2. Only ciphertext (VX1:) ever reaches Instagram's send box — never plaintext.
 *   3. Fail-closed: typing in Instagram's own box is BLOCKED (never encrypted-from-or-sent).
 *   4. Full key exchange through the DOM between two devices, then messaging with
 *      forward-secret chains; re-rendering a bubble does not raise false replay errors.
 *   5. Sending is blocked until the safety code is verified (default).
 *   6. Option B Zero-Knowledge Encrypted Relay: uploads a high-resolution image encrypted
 *      with a one-time AES-256-GCM key (`VX1B`), sends EXACTLY 1 `VX1:` message in Instagram,
 *      and the receiver downloads, verifies SHA-256, decrypts, and renders `<img class="vx-img">`.
 *   7. Offline fallback: if the relay is unreachable, multi-chunk in-band image encryption
 *      still reassembles into a single `<img>` bubble.
 */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const { JSDOM } = require("./dom_harness.js");
const { makeParty } = require("./helpers.js");
const { createRelayHandler } = require("../server/local-relay.js");

const SOURCE_FILES = ["crypto", "protocol", "util", "store", "session", "styles", "dom", "ui", "content"]
  .map((name) => path.join(__dirname, "..", "src", name + ".js"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const THREAD = "5551234";

function makeRelayFetch(relay) {
  return async function vxRelayFetch(urlStr, init = {}) {
    const parsed = new URL(urlStr);
    const headers = {};
    if (init.headers) {
      for (const [k, v] of Object.entries(init.headers)) headers[k.toLowerCase()] = v;
    }
    const bodyBytes = init.body ? new Uint8Array(init.body) : new Uint8Array(0);
    const res = await relay.handleRequest({
      method: init.method || "GET",
      path: parsed.pathname,
      origin: parsed.origin,
      headers,
      bodyBytes,
    });
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      json: async () => res.json,
      arrayBuffer: async () => {
        const b = res.binary || new Uint8Array(0);
        return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
      },
    };
  };
}

function createChromeStub() {
  const data = {};
  const changeListeners = [];
  const messageListeners = [];
  const fire = (changes) => changeListeners.forEach((fn) => fn(changes, "local"));
  const clone = (x) => JSON.parse(JSON.stringify(x));
  return {
    data, messageListeners,
    runtime: {
      id: "test-extension",
      getURL: (rel) => `chrome-extension://test-extension/${rel.replace(/^\//, "")}`,
      onMessage: { addListener: (fn) => messageListeners.push(fn) },
      sendMessage(message, callback) {
        return new Promise((resolve) => {
          const done = (reply) => { if (typeof callback === "function") callback(reply); resolve(reply); };
          for (const fn of messageListeners) fn(message, { id: "test-extension", tab: { id: 1 } }, done);
        });
      },
    },
    storage: {
      onChanged: { addListener: (fn) => changeListeners.push(fn) },
      local: {
        async get(keys) {
          if (keys === null) return clone(data);
          const out = {};
          for (const key of Array.isArray(keys) ? keys : [keys]) if (key in data) out[key] = clone(data[key]);
          return out;
        },
        async set(values) {
          const changes = {};
          for (const [k, v] of Object.entries(values)) { changes[k] = { oldValue: data[k], newValue: v }; data[k] = clone(v); }
          fire(changes);
        },
        async remove(key) {
          const changes = {};
          for (const k of Array.isArray(key) ? key : [key]) { changes[k] = { oldValue: data[k], newValue: undefined }; delete data[k]; }
          fire(changes);
        },
      },
    },
  };
}

function makeMessage(w, text) {
  const bubble = w.document.createElement("div");
  const span = w.document.createElement("span");
  span.setAttribute("dir", "auto");
  span.textContent = text;
  bubble.appendChild(span);
  return bubble;
}

async function createDevice(initialStorage = {}, options = {}) {
  const dom = new JSDOM(
    `<!DOCTYPE html><body>
       <div role="main">
         <div id="msgs"></div>
         <div id="box" role="textbox" contenteditable="true"></div>
         <button id="send" aria-label="Send">Send</button>
       </div>
     </body>`,
    { url: `https://www.instagram.com/direct/t/${THREAD}/`, pretendToBeVisual: true, runScripts: "outside-only" }
  );
  const w = dom.window;
  const chrome = createChromeStub();
  Object.assign(chrome.data, JSON.parse(JSON.stringify(initialStorage)));

  Object.defineProperty(w.HTMLElement.prototype, "offsetParent", { get() { return this.parentNode; }, configurable: true });
  Object.defineProperty(w.HTMLElement.prototype, "innerText", {
    get() { return this.textContent; }, set(v) { this.textContent = v; }, configurable: true,
  });
  w.document.execCommand = (command, _ui, value) => {
    if (command === "insertText") w.document.getElementById("box").textContent = value;
    return true;
  };
  Object.defineProperty(w, "crypto", { value: webcrypto, configurable: true });
  w.TextEncoder = TextEncoder;
  w.TextDecoder = TextDecoder;
  w.CSSStyleSheet = class { replaceSync() {} };
  w.chrome = chrome;
  if (options.relayFetch) {
    w.vxRelayFetch = options.relayFetch;
  }

  const shadows = [];
  const originalAttach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (init) {
    const root = originalAttach.call(this, { ...init, mode: "open" });
    shadows.push({ host: this, root });
    return root;
  };

  const sentLog = [];
  const pageCaptureEvents = [];
  const pageWindowMessages = [];
  const box = w.document.getElementById("box");
  const msgs = w.document.getElementById("msgs");

  w.addEventListener("message", (e) => pageWindowMessages.push(e.data));
  for (const target of [w, w.document]) {
    target.addEventListener("beforeinput", (e) => { if (e.data) pageCaptureEvents.push({ type: "beforeinput", data: e.data }); }, true);
    target.addEventListener("keydown", (e) => { if (e.target && e.target !== box && e.key) pageCaptureEvents.push({ type: "keydown", key: e.key }); }, true);
  }

  function instagramSend() {
    const text = box.textContent;
    if (!text) return;
    sentLog.push(text);
    msgs.appendChild(makeMessage(w, text));
    box.textContent = "";
  }
  w.document.getElementById("send").addEventListener("click", instagramSend);
  box.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); instagramSend(); } });

  for (const file of SOURCE_FILES) w.eval(fs.readFileSync(file, "utf8"));
  await sleep(300);

  let iframeDom = null;
  const composerShadow = shadows.find((s) => s.host.getAttribute("data-vx-composer-host") === "1" && s.host.isConnected);
  const iframeEl = composerShadow ? composerShadow.root.querySelector("iframe") : null;
  if (iframeEl && iframeEl.src) {
    iframeDom = await JSDOM.fromFile(path.join(__dirname, "..", "composer", "composer.html"), {
      url: iframeEl.src,
      parentWindow: w,
      beforeParse(iw) {
        iw.chrome = chrome;
        Object.defineProperty(iw, "crypto", { value: webcrypto, configurable: true });
        iw.TextEncoder = TextEncoder;
        iw.TextDecoder = TextDecoder;
        if (options.relayFetch) {
          iw.vxRelayFetch = options.relayFetch;
        }
      },
    });
    iframeEl.contentWindow = iframeDom.window;
    await sleep(150);
  }

  const device = {
    w, chrome, shadows, sentLog, pageCaptureEvents, pageWindowMessages, box, msgs, iframeDom,
    composerShadow,
    plainTexts: () => shadows.filter((s) => s.host.isConnected).map((s) => s.root.querySelector(".plain")).filter(Boolean).map((e) => e.textContent),
    statusTexts: () => shadows.filter((s) => s.host.isConnected).map((s) => s.root.querySelector(".status")).filter(Boolean).map((e) => e.textContent),
    revealedImages: () => shadows.filter((s) => s.host.isConnected && !s.host.hidden).map((s) => s.root.querySelector(".vx-img")).filter(Boolean),
    toast: () => {
      const found = shadows.map((s) => s.root.querySelector(".toast")).filter((t) => t && t.isConnected);
      return found.length ? found[found.length - 1] : null;
    },
    receive: (text) => msgs.appendChild(makeMessage(w, text)),
    composerInput: () => iframeDom.window.document.getElementById("composeInput"),
    composerStatus: () => iframeDom.window.document.getElementById("statusLabel").textContent,
    typeInVeilxComposerAndSend(text) {
      const iw = iframeDom.window;
      const ta = iw.document.getElementById("composeInput");
      ta.dispatchEvent(new iw.Event("beforeinput", { bubbles: true, cancelable: true, composed: true, data: text }));
      ta.value = text;
      ta.dispatchEvent(new iw.Event("input", { bubbles: true, composed: true }));
      ta.dispatchEvent(new iw.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, composed: true }));
    },
    typeInInstagramBoxAndPressEnter(text) {
      box.textContent = text;
      const e = new w.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true });
      box.dispatchEvent(e);
      return e;
    },
    popup: (message) => new Promise((resolve) => chrome.messageListeners[0](message, { id: "test-extension" }, resolve)),
  };
  return device;
}

/** Produce two established, verified parties' storage (as the real handshake would). */
async function establishedStorages({ verified = true } = {}) {
  const A = makeParty(), B = makeParty();
  const offer = await A.session.createOffer(THREAD);
  const [entry] = B.protocol.reassembleKeyPackets(offer.packets);
  const [ev] = await B.session.processKeyEntries(THREAD, [entry]);
  const reply = await B.session.acceptOffer(THREAD, ev.entry);
  await A.session.processKeyEntries(THREAD, A.protocol.reassembleKeyPackets([...offer.packets, ...reply.packets]));
  if (verified) { await A.store.verifyConversation(THREAD); await B.store.verifyConversation(THREAD); }
  return { a: A.data, b: B.data };
}

test("composer is the extension iframe only: no text field in the page, native box hidden, zero event/message leaks", async () => {
  const { a } = await establishedStorages();
  const d = await createDevice(a);
  assert.ok(d.iframeDom, "extension-origin iframe mounted");
  assert.match(d.w.document.querySelector("iframe, [data-vx-composer-host]") ? "ok" : "", /ok/);
  const root = d.composerShadow.root;
  assert.equal(root.querySelector("textarea"), null, "no in-page textarea exists");
  assert.equal(d.box.getAttribute("data-veilx-hidden-composer"), "1");
  assert.match(root.querySelector("iframe").src, /^chrome-extension:\/\/test-extension\/composer\/composer\.html/);
  assert.equal(root.querySelector("iframe").getAttribute("allow"), "microphone", "only microphone permission delegated for encrypted voice notes");

  d.typeInVeilxComposerAndSend("super secret plan");
  await sleep(600);
  assert.equal(d.pageCaptureEvents.length, 0);
  assert.equal(d.pageWindowMessages.length, 0);
});

test("only VX1 ciphertext reaches Instagram's send box; the receiver decrypts it; re-render shows no false replay", async () => {
  const { a, b } = await establishedStorages();
  const sender = await createDevice(a);
  const receiver = await createDevice(b);

  sender.typeInVeilxComposerAndSend("meet at 7 \u{1F510}");
  await sleep(700);
  assert.equal(sender.sentLog.length, 1);
  assert.match(sender.sentLog[0], /^VX1:[A-Za-z0-9+/]+=*$/);
  assert.ok(!sender.sentLog.join("").includes("meet at 7"));
  assert.ok(!JSON.stringify(sender.chrome.data).includes("undefined"));

  receiver.receive(sender.sentLog[0]);
  await sleep(600);
  assert.deepEqual(receiver.plainTexts(), ["meet at 7 \u{1F510}"]);
  assert.ok(receiver.statusTexts().some((t) => t.includes("🔓")));

  receiver.msgs.replaceChildren();
  receiver.receive(sender.sentLog[0]);
  await sleep(600);
  assert.deepEqual(receiver.plainTexts().filter((t) => t === "meet at 7 \u{1F510}").length >= 1, true);
  assert.ok(!receiver.statusTexts().some((t) => /replay/i.test(t)));

  sender.receive(sender.sentLog[0]);
  await sleep(600);
  assert.ok(sender.plainTexts().includes("meet at 7 \u{1F510}"));
});

test("fail-closed: typing in Instagram's own box is blocked, never encrypted-from or sent", async () => {
  const { a } = await establishedStorages();
  const d = await createDevice(a);
  const evt = d.typeInInstagramBoxAndPressEnter("this must never leave");
  await sleep(250);
  assert.equal(evt.defaultPrevented, true);
  assert.equal(d.sentLog.length, 0, "nothing sent");
  assert.ok(d.toast(), "user is told why");
  assert.match(d.toast().textContent, /not private/i);
  d.box.textContent = "also blocked";
  d.w.document.getElementById("send").click();
  await sleep(150);
  assert.equal(d.sentLog.length, 0);
});

test("with VeilX switched off, Instagram's native composer works normally", async () => {
  const { a } = await establishedStorages();
  const d = await createDevice({ ...a, enabled: false });
  d.typeInInstagramBoxAndPressEnter("plain chat");
  await sleep(150);
  assert.deepEqual(d.sentLog, ["plain chat"]);
});

test("sending is blocked until the safety code is verified (default)", async () => {
  const { a } = await establishedStorages({ verified: false });
  const d = await createDevice(a);
  assert.match(d.composerStatus(), /Verify/);
  d.typeInVeilxComposerAndSend("should not send");
  await sleep(500);
  assert.equal(d.sentLog.length, 0);
});

test("full key exchange through the page, then messaging (A offers, B accepts, both verify)", async () => {
  const A = await createDevice();
  const B = await createDevice();

  const res = await A.popup({ type: "VX_START_EXCHANGE" });
  assert.equal(res.ok, true, res.error);
  assert.ok(A.sentLog.length >= 2);
  assert.ok(A.sentLog.every((t) => t.startsWith("VX1K:")));

  for (const t of A.sentLog) B.receive(t);
  await sleep(700);
  const toast = B.toast();
  assert.ok(toast, "B is asked to accept");
  assert.match(toast.textContent, /key-exchange|key exchange/i);
  const accept = B.shadows.map((s) => s.root.querySelector(".toast-action")).filter(Boolean).pop();
  accept.click();
  await sleep(1200);
  assert.ok(B.sentLog.length >= 2 && B.sentLog.every((t) => t.startsWith("VX1K:")), "B posted its reply");

  for (const t of B.sentLog) A.receive(t);
  await sleep(1000);
  const stA = JSON.stringify(A.chrome.data), stB = JSON.stringify(B.chrome.data);
  for (const st of [stA, stB]) {
    assert.ok(!st.includes("ecPrivJwk") && !st.includes("rootB64"), "no ephemeral/root secrets persisted");
  }
  const recA = A.chrome.data[`conv:${THREAD}`], recB = B.chrome.data[`conv:${THREAD}`];
  assert.ok(recA.convId && recA.convId === recB.convId);
  assert.equal(recA.safetyCode, recB.safetyCode);

  for (const d of [A, B]) {
    const rec = d.chrome.data[`conv:${THREAD}`];
    await d.chrome.storage.local.set({ [`conv:${THREAD}`]: { ...rec, verified: true } });
  }
  await sleep(300);
  A.typeInVeilxComposerAndSend("hello over a forward-secret channel");
  await sleep(800);
  const blob = A.sentLog.find((t) => t.startsWith("VX1:"));
  assert.ok(blob);
  B.receive(blob);
  await sleep(700);
  assert.ok(B.plainTexts().includes("hello over a forward-secret channel"));
});

test("Option B Zero-Knowledge Relay: encrypts a large HD image into VX1B, sends ONLY 1 Instagram DM, and decrypts into <img>", async () => {
  const { a, b } = await establishedStorages();
  const relay = createRelayHandler();
  const relayFetch = makeRelayFetch(relay);

  const sender = await createDevice(a, { relayFetch });
  const receiver = await createDevice(b, { relayFetch });

  // Simulate a 120 KB High-Definition WebP photo (which would have been ~270 messages in-band!)
  const hdRawBytes = Buffer.alloc(120 * 1024, 0xcd);
  const hdDataUrl = `data:image/webp;base64,${hdRawBytes.toString("base64")}`;

  const sendRes = await sender.iframeDom.window.vxSendImageDataUrl(hdDataUrl, { requireSidecar: true });
  assert.equal(sendRes.ok, true, sendRes.error);
  assert.equal(sendRes.mode, "sidecar");
  assert.equal(sendRes.parts, 1, "Option B sends EXACTLY 1 message in Instagram Direct");
  assert.equal(sender.sentLog.length, 1);
  assert.match(sender.sentLog[0], /^VX1:[A-Za-z0-9+/]+=*$/);
  assert.equal(relay.store.size, 1, "encrypted VX1B blob stored on relay");

  // Receiver receives that SINGLE VX1: message, downloads VX1B from the relay, verifies SHA-256, and renders <img>
  receiver.receive(sender.sentLog[0]);
  await sleep(700);

  const imgs = receiver.revealedImages();
  assert.equal(imgs.length, 1);
  assert.equal(imgs[0].src, hdDataUrl);
  assert.ok(receiver.statusTexts().some((t) => t.includes("R2 Relay · 1 DM")));
});

test("offline fallback: when relay is unreachable, multi-message in-band image encryption still reassembles one <img>", async () => {
  const { a, b } = await establishedStorages();
  const sender = await createDevice(a);
  const receiver = await createDevice(b);

  const fakePayloadB64 = Buffer.alloc(4800, 0xab).toString("base64");
  const hdDataUrl = `data:image/webp;base64,${fakePayloadB64}`;

  const sendRes = await sender.iframeDom.window.vxSendImageDataUrl(hdDataUrl, { forceInBand: true });
  assert.equal(sendRes.ok, true, sendRes.error);
  assert.equal(sendRes.mode, "inband");
  assert.ok(sendRes.parts >= 8);
  assert.equal(sender.sentLog.length, sendRes.parts);

  for (const pkt of sender.sentLog) receiver.receive(pkt);
  await sleep(900);

  const imgs = receiver.revealedImages();
  assert.equal(imgs.length, 1, "intermediate chunk bubbles are collapsed into a single HD image bubble");
  assert.equal(imgs[0].src, hdDataUrl);
});

test("Original-fidelity media sidecar: preserves exact original bytes for images, short videos (<video>), and voice notes (<audio>) in 1 DM", async () => {
  const { a, b } = await establishedStorages();
  const relay = createRelayHandler();
  const relayFetch = makeRelayFetch(relay);

  const sender = await createDevice(a, { relayFetch });
  const receiver = await createDevice(b, { relayFetch });

  const makeFileObj = (u8, type) => ({
    type,
    size: u8.byteLength,
    arrayBuffer: async () => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength),
  });

  // 1. Original PNG bytes (verified bit-for-bit without canvas re-encoding)
  const originalPngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xde, 0xad, 0xbe, 0xef]);
  const resImg = await sender.iframeDom.window.vxHandleMediaFile(makeFileObj(originalPngBytes, "image/png"));
  assert.equal(resImg.ok, true, resImg.error);
  assert.equal(resImg.mode, "sidecar");
  assert.equal(resImg.parts, 1);

  receiver.receive(sender.sentLog[0]);
  await sleep(600);
  const imgs = receiver.revealedImages();
  assert.equal(imgs.length, 1);
  assert.equal(imgs[0].src, `data:image/png;base64,${Buffer.from(originalPngBytes).toString("base64")}`);

  // 2. Encrypted short video (video/mp4 -> renders <video class="vx-video">)
  const videoBytes = new Uint8Array([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x70, 0x34, 0x32]);
  const resVid = await sender.iframeDom.window.vxHandleMediaFile(makeFileObj(videoBytes, "video/mp4"));
  assert.equal(resVid.ok, true, resVid.error);
  assert.equal(resVid.parts, 1);

  receiver.receive(sender.sentLog[1]);
  await sleep(600);
  const videos = receiver.shadows
    .filter((s) => s.host.isConnected && !s.host.hidden)
    .map((s) => s.root.querySelector(".vx-video"))
    .filter(Boolean);
  assert.equal(videos.length, 1, "decrypted short video rendered inside closed Shadow DOM <video>");
  assert.equal(videos[0].src, `data:video/mp4;base64,${Buffer.from(videoBytes).toString("base64")}`);

  // 3. Encrypted voice note (audio/webm -> renders <audio class="vx-audio">)
  const voiceBytes = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01]);
  const resAud = await sender.iframeDom.window.vxHandleMediaFile(makeFileObj(voiceBytes, "audio/webm"));
  assert.equal(resAud.ok, true, resAud.error);
  assert.equal(resAud.parts, 1);

  receiver.receive(sender.sentLog[2]);
  await sleep(600);
  const audios = receiver.shadows
    .filter((s) => s.host.isConnected && !s.host.hidden)
    .map((s) => s.root.querySelector(".vx-audio"))
    .filter(Boolean);
  assert.equal(audios.length, 1, "decrypted voice note rendered inside closed Shadow DOM <audio>");
  assert.equal(audios[0].src, `data:audio/webm;base64,${Buffer.from(voiceBytes).toString("base64")}`);
});
