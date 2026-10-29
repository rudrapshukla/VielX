/**
 * src/background.js — VeilX 1.0.0 service worker.
 *
 * 1. IPC broker: relays commands from the extension-origin composer to the
 *    Instagram page script of the SAME tab (no window.postMessage involved),
 *    and executes privileged Zero-Knowledge Relay uploads/downloads (`VX_RELAY_UPLOAD`,
 *    `VX_RELAY_DOWNLOAD`) outside the page/iframe CORS & Private Network Access sandbox.
 *
 * 2. Studio network rules (declarativeNetRequest). These are what let the
 *    Instagram web app run inside the Studio tab's iframe.
 */

(function () {
  "use strict";

  const RULE_BASE = 10000;
  const RULES_PER_TAB = 8;

  function ruleIdsForTab(tabId) {
    const start = RULE_BASE + (tabId % 100000) * RULES_PER_TAB;
    return Array.from({ length: RULES_PER_TAB }, (_, i) => start + i);
  }

  /** Pure builder (exported for tests). Every rule carries `tabIds`. */
  function buildStudioRules(tabId) {
    const ids = ruleIdsForTab(tabId);
    const tabIds = [tabId];
    return [
      {
        id: ids[0], priority: 1,
        action: {
          type: "modifyHeaders",
          responseHeaders: [
            { header: "x-frame-options", operation: "remove" },
            { header: "content-security-policy", operation: "remove" },
            { header: "content-security-policy-report-only", operation: "remove" },
          ],
        },
        condition: { tabIds, requestDomains: ["instagram.com"], resourceTypes: ["sub_frame"] },
      },
      {
        id: ids[1], priority: 2,
        action: { type: "modifyHeaders", requestHeaders: [{ header: "sec-fetch-dest", operation: "set", value: "document" }] },
        condition: { tabIds, requestDomains: ["instagram.com"], resourceTypes: ["sub_frame"] },
      },
      {
        id: ids[2], priority: 2,
        action: {
          type: "modifyHeaders",
          requestHeaders: [
            { header: "origin", operation: "set", value: "https://www.instagram.com" },
            { header: "referer", operation: "set", value: "https://www.instagram.com/" },
          ],
        },
        condition: {
          tabIds, requestDomains: ["instagram.com", "facebook.com"],
          resourceTypes: ["xmlhttprequest", "websocket", "ping", "other"],
        },
      },
      {
        id: ids[3], priority: 3,
        action: { type: "block" },
        condition: { tabIds, urlFilter: "*instagram.com/*service-worker*", resourceTypes: ["script", "other"] },
      },
    ];
  }

  async function installStudioRules(tabId) {
    const dnr = chrome.declarativeNetRequest;
    await dnr.updateSessionRules({ removeRuleIds: ruleIdsForTab(tabId), addRules: buildStudioRules(tabId) });
  }

  async function removeStudioRules(tabId) {
    try {
      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ruleIdsForTab(tabId) });
    } catch (_) {}
  }

  async function cleanupOrphanRules() {
    try {
      const [rules, tabs] = await Promise.all([
        chrome.declarativeNetRequest.getSessionRules(),
        chrome.tabs.query({}),
      ]);
      const live = new Set(tabs.map((t) => t.id));
      const orphans = rules
        .filter((r) => r.condition && Array.isArray(r.condition.tabIds) && !r.condition.tabIds.some((id) => live.has(id)))
        .map((r) => r.id);
      const legacy = rules.filter((r) => !(r.condition && r.condition.tabIds)).map((r) => r.id);
      const remove = [...orphans, ...legacy];
      if (remove.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: remove });
    } catch (err) {
      console.warn("[VeilX] rule cleanup failed:", err);
    }
  }

  async function purgeLegacySecrets() {
    try {
      const all = await chrome.storage.local.get(null);
      const doomed = Object.entries(all)
        .filter(([k, v]) => k === "identity" || k === "ownPastKeys" ||
          (k.startsWith("conv:") && v && typeof v === "object" && !v.convId && !v.offer))
        .map(([k]) => k);
      for (const k of doomed) {
        await chrome.storage.local.set({ [k]: "x".repeat(64) });
        await chrome.storage.local.remove(k);
      }
    } catch (err) {
      console.warn("[VeilX] legacy cleanup failed:", err);
    }
  }

  function bytesToBase64(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
    const CHUNK = 0x8000;
    if (u8.length <= CHUNK) return btoa(String.fromCharCode.apply(null, u8));
    const parts = [];
    for (let i = 0; i < u8.length; i += CHUNK) {
      parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK)));
    }
    return btoa(parts.join(""));
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function handleRelayUpload(message) {
    if (typeof fetch !== "function") throw new Error("Service worker fetch unavailable.");
    const bodyBytes = base64ToBytes(message.bodyB64 || "");
    const resp = await fetch(message.url, {
      method: "POST",
      headers: message.headers || {},
      body: bodyBytes,
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || !data.ok) {
      throw new Error((data && data.error) || `Relay HTTP ${resp.status}`);
    }
    return { ok: true, data };
  }

  async function handleRelayDownload(message) {
    if (typeof fetch !== "function") throw new Error("Service worker fetch unavailable.");
    const resp = await fetch(message.url, { method: "GET" });
    if (!resp.ok) {
      throw new Error(`Relay download HTTP ${resp.status}`);
    }
    const bytes = new Uint8Array(await resp.arrayBuffer());
    return { ok: true, bodyB64: bytesToBase64(bytes) };
  }

  const URL_COMPOSER = () => chrome.runtime.getURL("composer/");
  const URL_POPUP = () => chrome.runtime.getURL("popup/");
  const URL_APP = () => chrome.runtime.getURL("app/");
  const fromPage = (sender, prefix) => typeof sender.url === "string" && sender.url.startsWith(prefix);

  const BROKER_TYPES = new Set([
    "VX_BROKER_SEND_CIPHERTEXT", "VX_BROKER_START_EXCHANGE", "VX_BROKER_ACCEPT_OFFER", "VX_BROKER_QUERY",
  ]);

  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (!message || sender.id !== chrome.runtime.id) return;

      // Privileged Zero-Knowledge Relay Upload (from composer iframe)
      if (message.type === "VX_RELAY_UPLOAD") {
        if (!fromPage(sender, URL_COMPOSER())) {
          sendResponse({ ok: false, error: "Not allowed." });
          return false;
        }
        handleRelayUpload(message).then(
          sendResponse,
          (err) => sendResponse({ ok: false, error: err.message || "Relay upload failed." })
        );
        return true;
      }

      // Privileged Zero-Knowledge Relay Download (from content script or composer)
      if (message.type === "VX_RELAY_DOWNLOAD") {
        handleRelayDownload(message).then(
          sendResponse,
          (err) => sendResponse({ ok: false, error: err.message || "Relay download failed." })
        );
        return true;
      }

      // Popup → open the VeilX Web Messenger (https://veilxweb.onrender.com).
      if (message.type === "VX_OPEN_STUDIO_APP" || message.type === "VX_OPEN_WEB_APP") {
        if (!fromPage(sender, URL_POPUP())) return;
        chrome.tabs.create({ url: "https://veilxweb.onrender.com" }).then(
          (tab) => sendResponse({ ok: true, tabId: tab ? tab.id : null, url: "https://veilxweb.onrender.com" }),
          (err) => sendResponse({ ok: false, error: err.message })
        );
        return true;
      }

      // Studio page → "install my rules, then I will load Instagram".
      if (message.type === "VX_STUDIO_READY") {
        if (!fromPage(sender, URL_APP()) || !sender.tab) return;
        installStudioRules(sender.tab.id).then(
          () => sendResponse({ ok: true }),
          (err) => sendResponse({ ok: false, error: err.message })
        );
        return true;
      }

      // Composer → page script of its own tab.
      if (BROKER_TYPES.has(message.type)) {
        if (!fromPage(sender, URL_COMPOSER())) {
          sendResponse({ ok: false, error: "Not allowed." });
          return false;
        }
        if (!sender.tab || typeof sender.tab.id !== "number") {
          sendResponse({ ok: false, error: "No Instagram tab found." });
          return false;
        }
        const innerType = message.type.replace("VX_BROKER_", "VX_");
        chrome.tabs
          .sendMessage(sender.tab.id, { ...message, type: innerType })
          .then(sendResponse)
          .catch((err) => sendResponse({ ok: false, error: err.message || "Tab unreachable." }));
        return true;
      }
    });

    chrome.tabs.onRemoved.addListener((tabId) => { removeStudioRules(tabId); });
    chrome.runtime.onStartup && chrome.runtime.onStartup.addListener(cleanupOrphanRules);
    chrome.runtime.onInstalled && chrome.runtime.onInstalled.addListener(() => { cleanupOrphanRules(); purgeLegacySecrets(); });
    cleanupOrphanRules();
    purgeLegacySecrets();
  }

  if (typeof module !== "undefined") module.exports = { buildStudioRules, ruleIdsForTab, purgeLegacySecrets };
})();
