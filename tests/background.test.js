/**
 * tests/background.test.js — network rules are tab-scoped and minimal; the broker
 * only serves the composer and only talks to the sender's own tab.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");

function loadBackground() {
  const state = { rules: [], listeners: [], removedListeners: [], sent: [], storage: {}, tabs: [{ id: 5 }, { id: 9 }] };
  globalThis.chrome = {
    runtime: {
      id: "ext", getURL: (p) => `chrome-extension://ext/${p}`,
      onMessage: { addListener: (fn) => state.listeners.push(fn) },
      onStartup: { addListener() {} }, onInstalled: { addListener() {} },
    },
    tabs: {
      onRemoved: { addListener: (fn) => state.removedListeners.push(fn) },
      query: async () => state.tabs,
      create: async (o) => ({ id: 77, url: o.url }),
      sendMessage: async (tabId, msg) => { state.sent.push({ tabId, msg }); return { ok: true }; },
    },
    storage: { local: {
      get: async () => JSON.parse(JSON.stringify(state.storage)),
      set: async (v) => Object.assign(state.storage, v),
      remove: async (k) => { delete state.storage[k]; },
    } },
    declarativeNetRequest: {
      getSessionRules: async () => state.rules.slice(),
      updateSessionRules: async ({ removeRuleIds = [], addRules = [] }) => {
        state.rules = state.rules.filter((r) => !removeRuleIds.includes(r.id)).concat(addRules);
      },
    },
  };
  delete require.cache[require.resolve("../src/background.js")];
  const mod = require("../src/background.js");
  return { state, mod };
}
const call = (state, message, sender) => new Promise((resolve) => {
  const r = state.listeners[0](message, { id: "ext", ...sender }, resolve);
  if (r !== true) setTimeout(() => resolve("NO-ASYNC-REPLY"), 20);
});

test("every Studio rule is scoped to one tab; nothing global, nothing on main_frame", () => {
  const { mod } = loadBackground();
  const rules = mod.buildStudioRules(5);
  assert.ok(rules.length >= 3);
  const all = JSON.stringify(rules);
  for (const r of rules) {
    assert.deepEqual(r.condition.tabIds, [5]);
    assert.ok(!(r.condition.resourceTypes || []).includes("main_frame"), "no main_frame");
  }
  for (const banned of ["cross-origin-opener-policy", "cross-origin-embedder-policy", "permissions-policy"]) {
    assert.ok(!all.includes(banned), banned + " must not be stripped");
  }
  // CSP / X-Frame-Options are removed only from the embedded iframe document, never from scripts/XHR.
  const strip = rules.find((r) => JSON.stringify(r.action).includes("x-frame-options"));
  assert.deepEqual(strip.condition.resourceTypes, ["sub_frame"]);
  assert.deepEqual(strip.condition.requestDomains, ["instagram.com"]);
});

test("rule ids do not collide between tabs", () => {
  const { mod } = loadBackground();
  const ids = new Set([...mod.buildStudioRules(5), ...mod.buildStudioRules(9)].map((r) => r.id));
  assert.equal(ids.size, mod.buildStudioRules(5).length * 2);
});

test("Studio rules are installed only when the Studio page asks, only for its own tab, and removed on close", async () => {
  const { state } = loadBackground();
  assert.equal(state.rules.length, 0, "nothing installed at start-up");
  // A page that is not the Studio cannot install rules.
  assert.equal(await call(state, { type: "VX_STUDIO_READY" }, { url: "https://www.instagram.com/", tab: { id: 5 } }), "NO-ASYNC-REPLY");
  assert.equal(state.rules.length, 0);
  const res = await call(state, { type: "VX_STUDIO_READY" }, { url: "chrome-extension://ext/app/app.html", tab: { id: 5 } });
  assert.equal(res.ok, true);
  assert.ok(state.rules.length > 0 && state.rules.every((r) => r.condition.tabIds[0] === 5));
  state.removedListeners[0](5);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(state.rules.length, 0);
});

test("start-up removes orphaned and legacy global rules", async () => {
  const { state } = (() => {
    const l = loadBackground();
    l.state.rules = [
      { id: 5001, condition: { requestDomains: ["instagram.com"] } },              // legacy global rule from old builds
      { id: 20000, condition: { tabIds: [404] } },                                  // tab no longer exists
      { id: 20001, condition: { tabIds: [5] } },                                    // live tab
    ];
    return l;
  })();
  delete require.cache[require.resolve("../src/background.js")];
  require("../src/background.js");
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(state.rules.map((r) => r.id), [20001]);
});

test("broker: only the composer may use it, and only toward the sender's own tab", async () => {
  const { state } = loadBackground();
  const msg = { type: "VX_BROKER_SEND_CIPHERTEXT", ciphertext: "VX1:AAAA", threadId: "t", tabId: 9 };
  const denied = await call(state, msg, { url: "https://www.instagram.com/direct/", tab: { id: 5 } });
  assert.equal(denied.ok, false);
  assert.equal(state.sent.length, 0);
  const ok = await call(state, msg, { url: "chrome-extension://ext/composer/composer.html?threadId=t", tab: { id: 5 } });
  assert.equal(ok.ok, true);
  assert.equal(state.sent[0].tabId, 5, "a spoofed message.tabId must be ignored");
  assert.equal(state.sent[0].msg.type, "VX_SEND_CIPHERTEXT");
});

test("only the popup can open the Studio tab", async () => {
  const { state } = loadBackground();
  assert.equal(await call(state, { type: "VX_OPEN_STUDIO_APP" }, { url: "https://www.instagram.com/" }), "NO-ASYNC-REPLY");
  assert.equal((await call(state, { type: "VX_OPEN_STUDIO_APP" }, { url: "chrome-extension://ext/popup/popup.html" })).ok, true);
});

test("older builds' long-term identity and static conversation keys are purged; new-format data is kept", async () => {
  const l = loadBackground();
  l.state.storage = {
    identity: { privateJwk: "old" }, ownPastKeys: ["a"],
    "conv:1": { keyB64: "oldkey", mode: "ecdh" },
    "conv:2": { convId: "new", mode: "pq" },
    "conv:3": { offer: { offerB64: "x" } },
    enabled: true,
  };
  await l.mod.purgeLegacySecrets();
  assert.deepEqual(Object.keys(l.state.storage).sort(), ["conv:2", "conv:3", "enabled"]);
});
