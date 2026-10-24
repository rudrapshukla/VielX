/**
 * src/dom.js — everything that touches Instagram's web page.
 *
 * WHY THIS FILE EXISTS
 *   Instagram does not offer an official way to plug into its chat, so this
 *   extension finds elements on the page using resilient selectors (combining
 *   ARIA roles, Lexical attributes, and Inssist-verified structure selectors).
 *   When Instagram updates its HTML, this is the ONLY file that needs fixing.
 *
 * SECURITY BOUNDARY FOR ON-PAGE COMPOSING
 *   Instagram's native composer (`[role="textbox"][contenteditable="true"]`)
 *   has React and Lexical input listeners attached in the page's main world.
 *   If a user types plaintext directly into Instagram's composer, Instagram's
 *   scripts can read every keystroke in real time.
 *   To prevent this while letting the user type directly on the website UI:
 *     1. We hide Instagram's native composer row (`data-veilx-hidden-composer="1"`)
 *        while keeping it mounted in the DOM so React does not crash.
 *     2. We mount VeilX's own closed-Shadow-DOM composer in its place.
 *     3. Only when the user presses Enter or Send—after AES-256-GCM encryption
 *        completes—do we atomically inject the `GPV2:...` ciphertext into
 *        Instagram's hidden Lexical input and trigger submission.
 */

globalThis.GPV = globalThis.GPV || {};

GPV.dom = (() => {
  "use strict";

  const INPUT_SELECTOR = [
    '.CometLexicalContentEditable[role="textbox"][contenteditable="true"]',
    '[role="textbox"][contenteditable="true"][data-lexical-editor="true"]',
    '[role="textbox"][contenteditable="true"]',
  ].join(", ");

  const COMPOSER_CONTAINER_SELECTORS = [
    "div:has(> .MWPCometComposerInner)",
    ".IGDOpenMessageListContainer + div > div > div",
  ];

  const SEND_SELECTOR = [
    'button[aria-label="Send"]',
    '[role="button"][aria-label="Send"]',
    'div[aria-label="Send"][role="button"]',
    'div[aria-label="Send"]',
    'button[type="submit"]',
  ].join(", ");

  const MESSAGE_TEXT_SELECTOR =
    'span[data-lexical-text="true"], span[dir="auto"], div[dir="auto"]';

  const CONVERSATION_PANE_SELECTOR = '.IGDInboxLayout, .IGDThreadDetail, [role="main"]';

  const PAGE_STYLE_ID = "veilx-nova-page-styles";
  const HIDDEN_ATTR = "data-veilx-hidden-composer";
  const HANDLED_ATTR = "data-gpv-handled";

  function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isDmPage() {
    return location.pathname.startsWith("/direct/");
  }

  function getThreadId() {
    return GPV.util.threadIdFromUrl(location.href);
  }

  function findMessageInput() {
    for (const box of document.querySelectorAll(INPUT_SELECTOR)) {
      if (
        box.offsetParent !== null ||
        box.hasAttribute(HIDDEN_ATTR) ||
        box.closest(`[${HIDDEN_ATTR}="1"]`)
      ) {
        return box;
      }
    }
    return null;
  }

  function findComposerContainer(input) {
    if (!input) return null;
    for (const sel of COMPOSER_CONTAINER_SELECTORS) {
      try {
        const match = input.closest(sel);
        if (match) return match;
      } catch (_) {}
    }
    return input;
  }

  function setNativeComposerHidden(input, hidden) {
    if (!input) return;
    const target = findComposerContainer(input) || input;
    if (hidden) {
      target.setAttribute(HIDDEN_ATTR, "1");
      input.setAttribute(HIDDEN_ATTR, "1");
    } else {
      target.removeAttribute(HIDDEN_ATTR);
      input.removeAttribute(HIDDEN_ATTR);
    }
  }

  function applyPageTheme(beautifyEnabled) {
    if (!document.head && !document.documentElement) return;
    let styleEl = document.getElementById(PAGE_STYLE_ID);
    if (!styleEl && GPV.styles && GPV.styles.pageThemeCss) {
      styleEl = document.createElement("style");
      styleEl.id = PAGE_STYLE_ID;
      styleEl.textContent = GPV.styles.pageThemeCss;
      (document.head || document.documentElement).appendChild(styleEl);
    }
    if (document.documentElement) {
      if (beautifyEnabled) {
        document.documentElement.setAttribute("data-veilx-ui", "beautiful");
      } else {
        document.documentElement.removeAttribute("data-veilx-ui");
      }
    }
  }

  function getConversationPane(input) {
    if (input) {
      // In a real browser layout on Instagram Direct, walk up from the composer
      // to find the right-hand active chat column BEFORE reaching the two-column
      // wrapper that also includes the left-hand Inbox thread list sidebar!
      const anchor =
        document.querySelector('[data-gpv-composer-host="1"]') || input;
      if (typeof anchor.getBoundingClientRect === "function") {
        let cur = anchor.parentElement || input.parentElement;
        while (cur && cur !== document.body) {
          const parent = cur.parentElement;
          if (!parent || parent === document.body) break;
          const curRect = cur.getBoundingClientRect();
          const parentRect = parent.getBoundingClientRect();
          if (
            curRect.width > 150 &&
            curRect.height > 150 &&
            curRect.left > 80 &&
            parentRect.left < curRect.left - 60
          ) {
            return cur;
          }
          cur = parent;
        }
      }
      const pane = input.closest(CONVERSATION_PANE_SELECTOR);
      if (pane) return pane;
    }
    return document.querySelector(CONVERSATION_PANE_SELECTOR);
  }

  function closestSendButton(element) {
    return element && element.closest ? element.closest(SEND_SELECTOR) : null;
  }

  function readInputText(input) {
    if (!input) return "";
    return (input.innerText || input.textContent || "")
      .replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "")
      .replace(/\r\n/g, "\n")
      .trim();
  }

  function replaceAllText(input, text) {
    if (typeof document.execCommand === "function") {
      document.execCommand("selectAll", false, null);
      document.execCommand("insertText", false, text);
    } else {
      input.textContent = text;
    }
  }

  async function writeInputText(input, text) {
    const expected = text.trim();

    input.focus();
    await wait(60);
    replaceAllText(input, text);
    await wait(50);
    if (readInputText(input) === expected) return true;

    input.innerHTML = "<p><br></p>";
    input.focus();
    await wait(40);
    replaceAllText(input, text);
    await wait(40);
    if (readInputText(input) === expected) return true;

    input.textContent = text;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    return readInputText(input) === expected;
  }

  function clickSendButton() {
    for (const button of document.querySelectorAll(SEND_SELECTOR)) {
      if (
        button.offsetParent !== null ||
        button.closest(`[${HIDDEN_ATTR}="1"]`)
      ) {
        button.click();
        return true;
      }
    }
    return false;
  }

  function pressEnter(input) {
    const evt = new KeyboardEvent("keydown", {
      key: "Enter",
      code: "Enter",
      keyCode: 13,
      which: 13,
      bubbles: true,
      cancelable: true,
    });
    Object.defineProperty(evt, "_veilxSynthetic", { value: true });
    input.dispatchEvent(evt);
  }

  function cleanMessageText(raw) {
    return (raw || "").replace(/[\u200B-\u200D\uFEFF\u00AD]+/g, "").trim();
  }

  function isSidebarOrPreviewElement(el) {
    if (!el || typeof el.closest !== "function") return false;
    if (
      el.closest(
        'nav, [role="navigation"], [aria-live="polite"], [aria-live="assertive"]'
      )
    ) {
      return true;
    }
    const link = el.closest("a");
    if (link && (link.getAttribute("href") || "").includes("/direct/")) {
      return true;
    }

    if (typeof el.getBoundingClientRect === "function") {
      const composerHost =
        document.querySelector('[data-gpv-composer-host="1"]') ||
        findMessageInput();
      if (composerHost && typeof composerHost.getBoundingClientRect === "function") {
        const compRect = composerHost.getBoundingClientRect();
        const elRect = el.getBoundingClientRect();
        if (
          compRect.width > 80 &&
          compRect.left > 80 &&
          elRect.width > 0 &&
          elRect.right <= compRect.left - 4
        ) {
          return true;
        }
      }
    }
    return false;
  }

  function findEncryptedElements(root, prefixes) {
    const results = [];
    if (!root) return results;

    for (const el of root.querySelectorAll(MESSAGE_TEXT_SELECTOR)) {
      if (
        el.getAttribute("role") === "textbox" ||
        el.getAttribute("contenteditable") === "true" ||
        el.closest(INPUT_SELECTOR)
      ) {
        continue;
      }

      if (isSidebarOrPreviewElement(el)) {
        continue;
      }

      const text = cleanMessageText(el.textContent);
      if (!prefixes.some((p) => text.startsWith(p))) continue;

      // ALWAYS skip outer containers (`div[dir="auto"]`) if any inner descendant
      // (`span[data-lexical-text="true"]` or `span[dir="auto"]`) also starts with
      // a GPV prefix! Modifying an outer `div[dir="auto"]` that also wraps Instagram's
      // "Sending..." status node breaks React Fiber reconciliation and causes duplicate
      // decryption of both the inner span and outer div!
      const hasInnerMatch = Array.from(
        el.querySelectorAll(MESSAGE_TEXT_SELECTOR)
      ).some((inner) =>
        prefixes.some((p) => cleanMessageText(inner.textContent).startsWith(p))
      );
      if (hasInnerMatch) continue;

      const next = el.nextElementSibling;
      const handled = Boolean(
        el.hasAttribute(HANDLED_ATTR) ||
          (next && next.hasAttribute("data-gpv-host")) ||
          el.querySelector(`[${HANDLED_ATTR}], [data-gpv-host]`)
      );

      results.push({ el, text, handled });
    }
    return results;
  }

  return {
    wait,
    isDmPage,
    getThreadId,
    findMessageInput,
    findComposerContainer,
    setNativeComposerHidden,
    applyPageTheme,
    getConversationPane,
    closestSendButton,
    readInputText,
    writeInputText,
    clickSendButton,
    pressEnter,
    findEncryptedElements,
  };
})();

if (typeof module !== "undefined") module.exports = GPV.dom;
