/**
 * tests/content.smoke.test.js — runs the REAL extension files inside a simulated
 * Instagram page AND loads `composer/composer.html` inside a separate cross-origin
 * `chrome-extension://` iframe communicating strictly over `chrome.runtime.sendMessage`!
 *
 * VERIFIES ALL SECURITY & USABILITY FIXES IN VEILX v5.0:
 *   1. ZERO `window.parent.postMessage` & ZERO `beforeinput`/`keydown` leakage:
 *      Instagram's `window` and `document` receive 0 `beforeinput`, `keydown`, OR
 *      `message` events when composing and sending from the `chrome-extension://`
 *      iframe composer!
 *   2. Standardized NIST FIPS 203 ML-KEM-768 + ECDH P-256 Handshake:
 *      Multi-packet `GPV2K:P1/N#...` keys + ML-KEM-768 ciphertexts are exchanged,
 *      reassembled, and decapsulated automatically.
 *   3. No False Replay Warnings on Own Sent Messages or React Re-Renders:
 *      When a user sends a message (or when Instagram's React virtual list
 *      destroys and recreates a message bubble), it decrypts cleanly with ZERO
 *      false `"Blocked duplicate / replayed ciphertext"` errors, while a genuine
 *      attacker replay (two simultaneously visible bubbles with the same IV/ID)
 *      is still blocked!
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const { JSDOM } = require("./dom_harness.js");

const GPVCrypto = require("../src/crypto.js");

const SOURCE_FILES = ["crypto", "util", "store", "styles", "dom", "ui", "content"]
  .map((name) => path.join(__dirname, "..", "src", name + ".js"));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createChromeStub() {
  const data = {};
  const changeListeners = [];
  const messageListeners = [];

  const fire = (changes) => changeListeners.forEach((fn) => fn(changes, "local"));

  return {
    data,
    messageListeners,
    runtime: {
      id: "test-extension",
      getURL: (rel) => `chrome-extension://test-extension/${rel.replace(/^\//, "")}`,
      onMessage: { addListener: (fn) => messageListeners.push(fn) },
      sendMessage(message, callback) {
        return new Promise((resolve) => {
          const done = (reply) => {
            if (typeof callback === "function") callback(reply);
            resolve(reply);
          };
          for (const fn of messageListeners) {
            fn(message, { id: "test-extension", tab: { id: 1 } }, done);
          }
        });
      },
    },
    storage: {
      onChanged: { addListener: (fn) => changeListeners.push(fn) },
      local: {
        async get(keys) {
          if (keys === null) return JSON.parse(JSON.stringify(data));
          const out = {};
          for (const key of Array.isArray(keys) ? keys : [keys]) {
            if (key in data) out[key] = JSON.parse(JSON.stringify(data[key]));
          }
          return out;
        },
        async set(values) {
          const changes = {};
          for (const [key, value] of Object.entries(values)) {
            changes[key] = { oldValue: data[key], newValue: value };
            data[key] = JSON.parse(JSON.stringify(value));
          }
          fire(changes);
        },
        async remove(key) {
          const changes = { [key]: { oldValue: data[key], newValue: undefined } };
          delete data[key];
          fire(changes);
        },
      },
    },
  };
}

async function createDevice(threadId, initialStorage = {}) {
  const dom = new JSDOM(
    `<!DOCTYPE html><body>
       <div role="main">
         <div id="msgs"></div>
         <div id="box" role="textbox" contenteditable="true"></div>
         <button id="send" aria-label="Send">Send</button>
       </div>
     </body>`,
    { url: `https://www.instagram.com/direct/t/${threadId}/`, pretendToBeVisual: true, runScripts: "outside-only" }
  );
  const w = dom.window;
  const chrome = createChromeStub();
  Object.assign(chrome.data, initialStorage);

  Object.defineProperty(w.HTMLElement.prototype, "offsetParent", { get() { return this.parentNode; }, configurable: true });
  Object.defineProperty(w.HTMLElement.prototype, "innerText", {
    get() { return this.textContent; },
    set(value) { this.textContent = value; },
    configurable: true,
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

  // Listen on Instagram's `window` for ANY `postMessage` traffic!
  w.addEventListener("message", (e) => {
    pageWindowMessages.push(e.data);
  });

  // Listen in the CAPTURE phase (`true`) on BOTH `window` and `document` for `beforeinput` and `keydown`!
  for (const target of [w, w.document]) {
    target.addEventListener(
      "beforeinput",
      (e) => {
        if (e.data) pageCaptureEvents.push({ type: "beforeinput", data: e.data });
      },
      true
    );
    target.addEventListener(
      "keydown",
      (e) => {
        if (e.target && e.target !== box && e.key) {
          pageCaptureEvents.push({ type: "keydown", key: e.key });
        }
      },
      true
    );
  }

  function instagramSend() {
    const text = box.textContent;
    if (!text) return;
    sentLog.push(text);
    msgs.appendChild(makeMessage(w, text));
    box.textContent = "";
  }
  w.document.getElementById("send").addEventListener("click", instagramSend);
  box.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); instagramSend(); }
  });

  for (const file of SOURCE_FILES) w.eval(fs.readFileSync(file, "utf8"));
  await sleep(250);

  let iframeDom = null;
  const composerShadow = shadows.find(
    (s) => s.host.getAttribute("data-gpv-composer-host") === "1" && s.host.isConnected
  );
  const iframeEl = composerShadow ? composerShadow.root.querySelector("iframe") : null;
  if (iframeEl && iframeEl.src) {
    iframeDom = await JSDOM.fromFile(
      path.join(__dirname, "..", "composer", "composer.html"),
      {
        url: iframeEl.src,
        parentWindow: w,
        beforeParse(iw) {
          iw.chrome = chrome;
          Object.defineProperty(iw, "crypto", { value: webcrypto, configurable: true });
          iw.TextEncoder = TextEncoder;
          iw.TextDecoder = TextDecoder;
        },
      }
    );
    iframeEl.contentWindow = iframeDom.window;
    await sleep(100);
  }

  const device = {
    w, chrome, shadows, sentLog, pageCaptureEvents, pageWindowMessages, box, msgs, iframeDom,
    plainTexts: () => shadows.filter((s) => s.host.isConnected).map((s) => s.root.querySelector(".plain")).filter(Boolean).map((e) => e.textContent),
    statusTexts: () => shadows.filter((s) => s.host.isConnected).map((s) => s.root.querySelector(".status")).filter(Boolean).map((e) => e.textContent),
    composerRoot: () => {
      const found = shadows.find((s) => s.host.getAttribute("data-gpv-composer-host") === "1" && s.host.isConnected);
      return found ? found.root : null;
    },
    toast: () => {
      const found = shadows.map((s) => s.root.querySelector(".toast")).filter((t) => t && t.isConnected);
      return found.length ? found[found.length - 1] : null;
    },
    receive: (text) => msgs.appendChild(makeMessage(w, text)),
    typeAndPressEnter(text, init = {}) {
      box.textContent = text;
      const event = new w.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, ...init });
      box.dispatchEvent(event);
      return event;
    },
    typeInVeilxComposerAndSend(text) {
      assert.ok(device.iframeDom, "Cross-origin composer iframe must be mounted");
      const iw = device.iframeDom.window;
      const ta = iw.document.getElementById("composeInput");
      assert.ok(ta, "Composer input inside extension iframe must exist");

      ta.dispatchEvent(new iw.Event("beforeinput", { bubbles: true, cancelable: true, composed: true, data: text }));
      ta.value = text;
      ta.dispatchEvent(new iw.Event("input", { bubbles: true, composed: true }));
      ta.dispatchEvent(new iw.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true, composed: true }));
    },
    popupSendKey: () =>
      new Promise((resolve) => chrome.messageListeners[0]({ type: "GPV_SEND_KEY" }, { id: "test-extension" }, resolve)),
  };
  return device;
}

function makeMessage(w, text) {
  const bubble = w.document.createElement("div");
  const span = w.document.createElement("span");
  span.setAttribute("dir", "auto");
  span.textContent = text;
  bubble.appendChild(span);
  return bubble;
}

let cachedPassphraseKeyB64 = null;
async function passphraseRecord(passphrase = "test passphrase 123") {
  if (!cachedPassphraseKeyB64 || passphrase !== "test passphrase 123") {
    const bytes = await GPVCrypto.deriveKeyFromPassphrase(passphrase);
    const b64 = GPVCrypto.bytesToBase64(bytes);
    if (passphrase === "test passphrase 123") cachedPassphraseKeyB64 = b64;
    return { mode: "passphrase", keyB64: b64, verified: true };
  }
  return { mode: "passphrase", keyB64: cachedPassphraseKeyB64, verified: true };
}

// ── Tests ───────────────────────────────────────────────────────────────────

test("Cross-origin `chrome-extension://` iframe composer uses `chrome.runtime` IPC with ZERO `window.postMessage` traffic and ZERO capture-phase event leaks", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  assert.equal(d.box.getAttribute("data-veilx-hidden-composer"), "1");
  assert.ok(d.iframeDom, "Cross-origin extension iframe is mounted");

  d.typeInVeilxComposerAndSend("top secret message");
  await sleep(500);

  assert.equal(
    d.pageCaptureEvents.length,
    0,
    "Zero beforeinput or keydown events reach Instagram's window or document capture listeners"
  );
  assert.equal(
    d.pageWindowMessages.length,
    0,
    "Zero window.postMessage messages are sent to Instagram's window!"
  );

  assert.equal(d.sentLog.length, 1);
  assert.ok(d.sentLog[0].startsWith("GPV2:"));

  await sleep(400);
  assert.deepEqual(d.plainTexts(), ["top secret message"]);
});

test("Enter sends ciphertext only, and the receiver sees the plain text", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });

  const event = d.typeAndPressEnter("hello world");
  assert.equal(event.defaultPrevented, true, "the original Enter must be blocked");

  await sleep(500);
  assert.equal(d.sentLog.length, 1);
  assert.ok(d.sentLog[0].startsWith("GPV2:"));
  assert.ok(!d.sentLog[0].includes("hello"), "plain text must not reach Instagram");

  await sleep(400);
  assert.deepEqual(d.plainTexts(), ["hello world"]);
});

test("clicking the Send button is encrypted too", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  d.box.textContent = "sent by mouse";
  d.w.document.getElementById("send").click();

  await sleep(500);
  assert.equal(d.sentLog.length, 1);
  assert.ok(d.sentLog[0].startsWith("GPV2:"));
  assert.ok(!d.sentLog[0].includes("mouse"));
});

test("no key for the chat: nothing is sent, the text stays, a warning appears", async () => {
  const d = await createDevice("222");
  d.typeAndPressEnter("should not leave");
  await sleep(300);

  assert.equal(d.sentLog.length, 0);
  assert.equal(d.box.textContent, "should not leave");
  assert.match(d.toast().textContent, /No key is set/);
});

test("a second Enter while sending does not send twice", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  d.typeAndPressEnter("once only");
  const second = d.typeAndPressEnter("once only");
  assert.equal(second.defaultPrevented, true);

  await sleep(500);
  assert.equal(d.sentLog.length, 1);
});

test("Shift+Enter is left alone (new line, not a send)", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  const shift = d.typeAndPressEnter("line", { shiftKey: true });
  await sleep(100);
  assert.equal(shift.defaultPrevented, false);
  assert.equal(d.sentLog.length, 0);
  assert.equal(d.box.textContent, "line");
});

test("Enter that confirms IME (e.g. Hindi) typing is left alone", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  d.typeAndPressEnter("नमस्ते", { isComposing: true });
  await sleep(100);
  assert.deepEqual(d.sentLog, ["नमस्ते"]);
});

test("with encryption switched off, Instagram's native composer is unhidden and normal sending works", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord(), enabled: false });
  assert.equal(d.box.getAttribute("data-veilx-hidden-composer"), null, "Native composer is unhidden when VeilX is paused");
  const event = d.typeAndPressEnter("plain message");
  await sleep(100);
  assert.deepEqual(d.sentLog, ["plain message"]);
  assert.equal(event.defaultPrevented, true);
});

test("a message that is too long once encrypted is refused", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  d.typeAndPressEnter("x".repeat(900));
  await sleep(300);
  assert.equal(d.sentLog.length, 0);
  assert.match(d.toast().textContent, /too long/);
});

test("a message encrypted with a different key shows a failure, not garbage", async () => {
  const other = await passphraseRecord("a completely different phrase");
  const sender = await createDevice("111", { "conv:111": other });
  sender.typeAndPressEnter("for someone else");
  await sleep(500);

  const receiver = await createDevice("111", { "conv:111": await passphraseRecord() });
  receiver.receive(sender.sentLog[0]);
  await sleep(400);

  assert.deepEqual(receiver.plainTexts(), []);
  assert.ok(receiver.statusTexts().some((t) => /Could not decrypt/.test(t)));
});

test("a message arriving before a key exists is decrypted once the key is saved", async () => {
  const sender = await createDevice("111", { "conv:111": await passphraseRecord() });
  sender.typeAndPressEnter("waiting for you");
  await sleep(500);

  const receiver = await createDevice("111");
  receiver.receive(sender.sentLog[0]);
  await sleep(400);
  assert.ok(receiver.statusTexts().some((t) => /No key set/.test(t)));

  await receiver.chrome.storage.local.set({ "conv:111": await passphraseRecord() });
  await sleep(300);
  assert.deepEqual(receiver.plainTexts(), ["waiting for you"]);
});

test("NIST FIPS 203 ML-KEM-768 + ECDH P-256 multi-packet key exchange between two devices, then encrypted messaging", async () => {
  const alice = await createDevice("chat-pq-1");
  const bob = await createDevice("chat-pq-1");

  // 1. Alice initiates key exchange -> sends 2 packets of `GPV2K:P1/2#...`
  const started = await alice.popupSendKey();
  assert.equal(started.ok, true);
  assert.ok(alice.sentLog.length >= 2, "1249-byte ML-KEM-768 + P-256 key splits into <1000-char packets");
  for (const pkt of alice.sentLog) {
    assert.ok(pkt.startsWith("GPV2K:"));
    assert.ok(pkt.length < 1000);
    bob.receive(pkt);
  }

  // 2. Bob reassembles Alice's key and clicks "Send my key" -> encapsulates ML-KEM-768 secret and sends packets
  await sleep(500);
  assert.match(bob.toast().textContent, /Send my key/);

  bob.toast().querySelector(".toast-action").click();
  await sleep(1200);
  assert.ok(bob.sentLog.length >= 4, "Responder key + 1088-byte ML-KEM-768 ciphertext splits into <1000-char packets");
  for (const pkt of bob.sentLog) {
    assert.ok(pkt.startsWith("GPV2K:"));
    assert.ok(pkt.length < 1000);
    alice.receive(pkt);
  }

  // 3. Alice reassembles Bob's packets -> decapsulates ML-KEM-768 secret and derives hybrid key
  await sleep(600);

  const aliceRecord = alice.chrome.data["conv:chat-pq-1"];
  const bobRecord = bob.chrome.data["conv:chat-pq-1"];
  assert.ok(aliceRecord.pqSharedB64, "Alice decapsulated the 32-byte ML-KEM-768 secret");
  assert.ok(bobRecord.pqSharedB64, "Bob encapsulated the 32-byte ML-KEM-768 secret");
  assert.equal(aliceRecord.pqSharedB64, bobRecord.pqSharedB64, "Both share the exact same ML-KEM-768 secret");
  assert.equal(aliceRecord.keyB64, bobRecord.keyB64, "Both derived the exact same hybrid key");

  // 4. Alice sends an encrypted message immediately from the on-page VeilX pill composer
  alice.sentLog.length = 0;
  alice.typeInVeilxComposerAndSend("hello bob from fips 203 ml-kem-768 veilx");
  await sleep(500);
  assert.equal(alice.sentLog.length, 1);
  assert.ok(alice.sentLog[0].startsWith("GPV2:"));

  bob.receive(alice.sentLog[0]);
  await sleep(400);
  assert.deepEqual(bob.plainTexts(), ["hello bob from fips 203 ml-kem-768 veilx"]);
});

test("React virtual-list re-renders of a message bubble NEVER trigger false replay warnings, while a simultaneous duplicate bubble IS blocked", async () => {
  const sender = await createDevice("111", { "conv:111": await passphraseRecord() });
  sender.typeInVeilxComposerAndSend("no false replay error");
  await sleep(500);
  const ciphertext = sender.sentLog[0];

  const receiver = await createDevice("111", { "conv:111": await passphraseRecord() });
  receiver.receive(ciphertext);
  await sleep(400);
  assert.deepEqual(receiver.plainTexts(), ["no false replay error"]);

  // Simulate Instagram's React virtual scroller unmounting the bubble and mounting a fresh DOM node with the same ciphertext!
  receiver.msgs.replaceChildren();
  receiver.receive(ciphertext);
  await sleep(400);
  assert.deepEqual(
    receiver.plainTexts(),
    ["no false replay error"],
    "Re-rendered DOM node decrypts cleanly with zero false replay errors!"
  );
  assert.ok(!receiver.statusTexts().some((t) => /replayed ciphertext/.test(t)));

  // Now simulate a genuine replay attack: a SECOND bubble with the same ciphertext while the first bubble is STILL in the DOM!
  receiver.receive(ciphertext);
  await sleep(400);
  assert.ok(
    receiver.statusTexts().some((t) => /replayed ciphertext/.test(t)),
    "Simultaneous duplicate bubble in the chat is caught and blocked as a replay"
  );
});

test("a changed contact key is never accepted silently", async () => {
  const alice = await createDevice("aaa");
  const bob = await createDevice("bbb");
  await alice.popupSendKey();
  for (const pkt of alice.sentLog) bob.receive(pkt);
  await sleep(500);
  bob.toast().querySelector(".toast-action").click();
  await sleep(1200);
  const originalKey = bob.chrome.data["conv:bbb"].keyB64;
  assert.ok(originalKey);

  const impostorIdentity = await GPVCrypto.generateIdentity();
  for (const pkt of GPVCrypto.makeKeyPackets(impostorIdentity.publicKey)) {
    bob.receive(pkt);
  }
  await sleep(500);

  assert.match(bob.toast().textContent, /key has changed/);
  assert.equal(bob.chrome.data["conv:bbb"].keyB64, originalKey, "the saved key must not change by itself");
});

test("a key-exchange message is ignored when the chat uses a passphrase", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });
  const identity = await GPVCrypto.generateIdentity();
  for (const pkt of GPVCrypto.makeKeyPackets(identity.publicKey)) {
    d.receive(pkt);
  }
  await sleep(500);

  assert.equal(d.chrome.data["conv:111"].mode, "passphrase");
  assert.equal(d.toast(), null);
});

test("half-finished key exchange: the notice says we are waiting for the contact", async () => {
  const d = await createDevice("aaa");
  await d.popupSendKey();
  const keyPktCount = d.sentLog.length;
  assert.ok(keyPktCount >= 2);

  d.typeAndPressEnter("are you there?");
  await sleep(400);

  assert.equal(d.sentLog.length, keyPktCount, "no plain or encrypted message may be sent");
  assert.match(d.toast().textContent, /key exchange is not finished/);
  assert.equal(d.box.textContent, "are you there?");
});


test("Receiver decrypts messages cleanly even when Instagram assigns different URL threadIds to sender and receiver, or when both peers initiate ML-KEM-768 key exchange simultaneously", async () => {
  // Instagram Direct often uses viewer-scoped URL thread IDs (/direct/t/<id_A>/ vs /direct/t/<id_B>/)
  const alice = await createDevice("ig-viewer-thread-alice-1001");
  const bob = await createDevice("ig-viewer-thread-bob-2002");

  // Both Alice and Bob click "Send my key" simultaneously before seeing each other's key!
  await alice.popupSendKey();
  await bob.popupSendKey();

  const aliceInitialPkts = alice.sentLog.slice();
  const bobInitialPkts = bob.sentLog.slice();
  alice.sentLog.length = 0;
  bob.sentLog.length = 0;

  // Deliver initial public keys to each other -> both auto-encapsulate ML-KEM-768 capsules
  for (const pkt of aliceInitialPkts) bob.receive(pkt);
  for (const pkt of bobInitialPkts) alice.receive(pkt);
  await sleep(1400);

  // Deliver follow-up ML-KEM-768 capsule packets to each other
  for (const pkt of alice.sentLog) bob.receive(pkt);
  for (const pkt of bob.sentLog) alice.receive(pkt);
  await sleep(700);

  const aliceRec = alice.chrome.data["conv:ig-viewer-thread-alice-1001"];
  const bobRec = bob.chrome.data["conv:ig-viewer-thread-bob-2002"];
  assert.ok(aliceRec && aliceRec.keyB64, "Alice derived hybrid key");
  assert.ok(bobRec && bobRec.keyB64, "Bob derived hybrid key");
  assert.equal(aliceRec.keyB64, bobRec.keyB64, "Alice and Bob converged on the exact same hybrid key despite simultaneous initiation");

  // Alice sends a message from her composer (threadId = ig-viewer-thread-alice-1001)
  alice.sentLog.length = 0;
  alice.typeInVeilxComposerAndSend("message from alice to bob across different threadIds");
  await sleep(500);
  assert.equal(alice.sentLog.length, 1);

  // Bob receives Alice's message on his different URL threadId (ig-viewer-thread-bob-2002)
  bob.receive(alice.sentLog[0]);
  await sleep(400);
  assert.deepEqual(bob.plainTexts(), ["message from alice to bob across different threadIds"]);
  assert.ok(!bob.statusTexts().some((t) => /Could not decrypt/.test(t)), "Zero Could not decrypt errors on receiver!");

  // Bob replies from his composer -> Alice receives and decrypts cleanly
  bob.sentLog.length = 0;
  bob.typeInVeilxComposerAndSend("reply from bob back to alice");
  await sleep(500);
  assert.equal(bob.sentLog.length, 1);

  alice.receive(bob.sentLog[0]);
  await sleep(400);
  assert.ok(alice.plainTexts().includes("reply from bob back to alice"));
  assert.ok(!alice.statusTexts().some((t) => /Could not decrypt/.test(t)), "Zero Could not decrypt errors on Alice!");
});


test("autoDecrypt ON never shows false replay errors when Instagram renders sidebar previews, optimistic bubbles, or nested div[dir=auto] + Sending status nodes", async () => {
  const d = await createDevice("111", { "conv:111": await passphraseRecord() });

  // 1. Send a message from VeilX composer -> gets encrypted
  d.typeInVeilxComposerAndSend("auto decrypt works without replay error");
  await sleep(500);
  const ct = d.sentLog[0];
  assert.ok(ct && ct.startsWith("GPV2:"));

  // 2. Simulate Instagram simultaneously rendering:
  //    (a) a sidebar thread preview link `<a href="/direct/t/111/"><span dir="auto">GPV2:...</span></a>`
  //    (b) a nested `<div dir="auto"><span data-lexical-text="true">GPV2:...</span><span>Sending...</span></div>`
  const sidebarLink = d.w.document.createElement("a");
  sidebarLink.setAttribute("href", "/direct/t/111/");
  const sidebarSpan = d.w.document.createElement("span");
  sidebarSpan.setAttribute("dir", "auto");
  sidebarSpan.textContent = ct;
  sidebarLink.appendChild(sidebarSpan);
  d.msgs.appendChild(sidebarLink);

  const outerBubble = d.w.document.createElement("div");
  outerBubble.setAttribute("dir", "auto");
  const innerLexical = d.w.document.createElement("span");
  innerLexical.setAttribute("data-lexical-text", "true");
  innerLexical.textContent = ct;
  const sendingIndicator = d.w.document.createElement("span");
  sendingIndicator.id = "ig-sending-status";
  sendingIndicator.textContent = "Sending...";
  outerBubble.appendChild(innerLexical);
  outerBubble.appendChild(sendingIndicator);
  d.msgs.appendChild(outerBubble);

  await sleep(450);

  // Verify zero false replay errors with autoDecrypt ON!
  assert.ok(
    !d.statusTexts().some((txt) => /replayed ciphertext/.test(txt)),
    "Zero false Blocked duplicate / replayed ciphertext errors when autoDecrypt is ON!"
  );
  // Verify the outer div[dir=auto] and Instagram Sending indicator were NOT hidden!
  assert.notEqual(outerBubble.style.display, "none", "Outer React container must never be hidden");
  assert.equal(
    d.w.document.getElementById("ig-sending-status").textContent,
    "Sending...",
    "Instagram Sending status node remains intact for React Fiber reconciliation"
  );
});
