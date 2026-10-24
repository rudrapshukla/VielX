/**
 * src/background.js — VeilX v5.2 Service Worker & Zero-`postMessage` Broker.
 *
 * TWO CRITICAL JOBS:
 *   1. Privileged Extension IPC Broker (`chrome.runtime.onMessage`):
 *      Relays ciphertext and key-exchange commands from `composer/composer.html`
 *      (running in the extension's `chrome-extension://` iframe) directly to
 *      `src/content.js` on the same tab (`sender.tab.id`) using `chrome.tabs.sendMessage`.
 *      This completely eliminates `window.parent.postMessage`, so Instagram's
 *      page scripts (`window.addEventListener("message", ...)`) NEVER see any
 *      message traffic between the VeilX composer and the content script!
 *   2. Inssist-Grade Standalone Web App Network & WebSocket Rules (`declarativeNetRequest`):
 *      - Strips `x-frame-options`, `content-security-policy`, and `permissions-policy`
 *        on `instagram.com` and `facebook.com`.
 *      - Sets `Sec-Fetch-Dest: document` on `sub_frame` navigations to `instagram.com`
 *        so Instagram's backend serves the full first-party Direct Messaging bundle.
 *      - Sets `Origin: https://www.instagram.com` on `xmlhttprequest` and `websocket`
 *        requests (`edge-chat.instagram.com`, `mqtt-mini.facebook.com`, GraphQL) so
 *        messages sent inside VeilX Studio (`app/app.html`) immediately receive their
 *        MQTT/GraphQL confirmation (never getting stuck on "Sending...") and real-time
 *        incoming messages never freeze!
 *      - Blocks Instagram's Service Worker registration script inside subframes so
 *        it cannot deadlock embedded frame requests.
 */

(function () {
  "use strict";

  const RULE_IDS = [5001, 5002, 5003, 5004, 5005];

  async function installStudioFrameRules() {
    if (
      typeof chrome === "undefined" ||
      !chrome.declarativeNetRequest ||
      !chrome.declarativeNetRequest.updateSessionRules
    ) {
      return;
    }
    try {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: RULE_IDS,
        addRules: [
          // Rule 5001: Strip framing, CSP, and permissions-policy restrictions on instagram.com & facebook.com
          {
            id: 5001,
            priority: 1,
            action: {
              type: "modifyHeaders",
              responseHeaders: [
                { header: "x-frame-options", operation: "remove" },
                { header: "content-security-policy", operation: "remove" },
                { header: "content-security-policy-report-only", operation: "remove" },
                { header: "permissions-policy", operation: "remove" },
                { header: "cross-origin-embedder-policy", operation: "remove" },
                { header: "cross-origin-opener-policy", operation: "remove" },
              ],
            },
            condition: {
              requestDomains: ["instagram.com", "facebook.com"],
              resourceTypes: [
                "main_frame",
                "sub_frame",
                "xmlhttprequest",
                "websocket",
                "script",
                "other",
              ],
            },
          },
          // Rule 5002: Make Instagram sub_frame requests look like top-level document navigations (Inssist technique)
          {
            id: 5002,
            priority: 2,
            action: {
              type: "modifyHeaders",
              requestHeaders: [
                { header: "sec-fetch-dest", operation: "set", value: "document" },
              ],
            },
            condition: {
              requestDomains: ["instagram.com"],
              resourceTypes: ["sub_frame"],
            },
          },
          // Rule 5003: Ensure XHR & WebSocket (MQTT real-time chat) carry Origin: https://www.instagram.com
          // so sent messages never hang on "Sending..." and incoming real-time messages never freeze!
          {
            id: 5003,
            priority: 2,
            action: {
              type: "modifyHeaders",
              requestHeaders: [
                {
                  header: "origin",
                  operation: "set",
                  value: "https://www.instagram.com",
                },
                {
                  header: "referer",
                  operation: "set",
                  value: "https://www.instagram.com/",
                },
              ],
            },
            condition: {
              requestDomains: ["instagram.com", "facebook.com"],
              resourceTypes: ["xmlhttprequest", "websocket", "ping", "other"],
            },
          },
          // Rule 5004: Block Instagram's service-worker script from registering inside the embedded Studio frame
          {
            id: 5004,
            priority: 3,
            action: {
              type: "block",
            },
            condition: {
              urlFilter: "*instagram.com/*service-worker*",
              resourceTypes: ["script", "other"],
            },
          },
        ],
      });
    } catch (err) {
      console.warn("[VeilX] Could not install studio frame rules:", err);
    }
  }

  installStudioFrameRules();

  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      installStudioFrameRules();
    });
  }

  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (!message || sender.id !== chrome.runtime.id) return;

      // Open the standalone VeilX Studio Web App in a new tab (like Inssist)
      if (message.type === "GPV_OPEN_STUDIO_APP") {
        const url = chrome.runtime.getURL("app/app.html");
        chrome.tabs.create({ url }).then(
          (tab) => sendResponse({ ok: true, tabId: tab ? tab.id : null }),
          (err) => sendResponse({ ok: false, error: err.message })
        );
        return true;
      }

      // Relay privileged commands from the composer iframe (or studio app) to the tab's content script
      if (
        [
          "GPV_BROKER_SEND_CIPHERTEXT",
          "GPV_BROKER_SEND_KEY",
          "GPV_BROKER_RESIZE_IFRAME",
        ].includes(message.type)
      ) {
        const targetTabId =
          (sender.tab && sender.tab.id) || message.tabId || null;
        if (targetTabId === null) {
          sendResponse({ ok: false, error: "No active Instagram tab found." });
          return false;
        }
        const innerType = message.type.replace("GPV_BROKER_", "GPV_");
        chrome.tabs
          .sendMessage(targetTabId, { ...message, type: innerType })
          .then(sendResponse)
          .catch((err) =>
            sendResponse({ ok: false, error: err.message || "Tab unreachable." })
          );
        return true;
      }
    });
  }
})();
