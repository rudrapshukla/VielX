/**
 * tests/dom_harness.js — Zero-dependency DOM, Cross-Origin Iframe, ShadowRoot
 * (with W3C composed event retargeting), and MutationObserver simulator for Node.js.
 */

"use strict";

const fs = require("node:fs");
const vm = require("node:vm");

let NativeJSDOM = null;
try {
  NativeJSDOM = require("jsdom").JSDOM;
} catch (_) {
  NativeJSDOM = null;
}

const COMPOSED_EVENTS = new Set([
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
  "click",
]);

class SimEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = Boolean(init.bubbles);
    this.cancelable = Boolean(init.cancelable);
    this.composed =
      init.composed !== undefined
        ? Boolean(init.composed)
        : COMPOSED_EVENTS.has(type);
    this.defaultPrevented = false;
    this._stopped = false;
    this._immediateStopped = false;
    this.target = null;
    this.currentTarget = null;
    Object.assign(this, init);
  }
  preventDefault() {
    if (this.cancelable) this.defaultPrevented = true;
  }
  stopPropagation() {
    this._stopped = true;
  }
  stopImmediatePropagation() {
    this._stopped = true;
    this._immediateStopped = true;
  }
}

class SimKeyboardEvent extends SimEvent {
  constructor(type, init = {}) {
    super(type, init);
    this.key = init.key || "";
    this.code = init.code || "";
    this.keyCode = init.keyCode || 0;
    this.which = init.which || 0;
    this.shiftKey = Boolean(init.shiftKey);
    this.isComposing = Boolean(init.isComposing);
  }
}

function matchesSingleSelector(el, sel) {
  if (!el || el.nodeType !== 1) return false;
  sel = sel.trim();
  if (!sel) return false;

  if (sel.includes(" ") && !sel.includes("[")) {
    const parts = sel.split(/\s+/);
    const last = parts.pop();
    if (!matchesSingleSelector(el, last)) return false;
    let cur = el.parentNode;
    while (cur && parts.length > 0) {
      if (matchesSingleSelector(cur, parts[parts.length - 1])) {
        parts.pop();
      }
      cur = cur.parentNode;
    }
    return parts.length === 0;
  }

  const attrRegex = /\[([a-zA-Z0-9_-]+)(?:="([^"]*)")?\]/g;
  let match;
  while ((match = attrRegex.exec(sel)) !== null) {
    const attrName = match[1];
    const attrVal = match[2];
    if (attrVal !== undefined) {
      if (el.getAttribute(attrName) !== attrVal) return false;
    } else {
      if (!el.hasAttribute(attrName)) return false;
    }
  }

  const withoutAttrs = sel.replace(attrRegex, "").trim();
  if (!withoutAttrs) return true;

  const idMatch = withoutAttrs.match(/#([a-zA-Z0-9_-]+)/);
  if (idMatch && el.id !== idMatch[1]) return false;

  const classMatches = withoutAttrs.match(/\.([a-zA-Z0-9_-]+)/g);
  if (classMatches) {
    for (const c of classMatches) {
      if (!el.classList.contains(c.slice(1))) return false;
    }
  }

  const tagMatch = withoutAttrs.match(/^[a-zA-Z0-9]+/);
  if (tagMatch && el.tagName.toLowerCase() !== tagMatch[0].toLowerCase()) {
    return false;
  }

  return true;
}

function matchesSelector(el, selectorGroup) {
  if (!el || el.nodeType !== 1 || !selectorGroup) return false;
  const parts = selectorGroup.split(",");
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes(":has(") || trimmed.includes("+")) continue;
    if (matchesSingleSelector(el, trimmed)) return true;
  }
  return false;
}

class SimClassList {
  constructor(el) {
    this._el = el;
  }
  _set() {
    return new Set(
      (this._el.className || "")
        .split(/\s+/)
        .map((s) => s.trim())
        .filter(Boolean)
    );
  }
  _save(set) {
    this._el.className = Array.from(set).join(" ");
  }
  add(...names) {
    const s = this._set();
    names.forEach((n) => s.add(n));
    this._save(s);
  }
  remove(...names) {
    const s = this._set();
    names.forEach((n) => s.delete(n));
    this._save(s);
  }
  contains(name) {
    return this._set().has(name);
  }
  toggle(name, force) {
    const s = this._set();
    const shouldHave = force !== undefined ? Boolean(force) : !s.has(name);
    if (shouldHave) s.add(name);
    else s.delete(name);
    this._save(s);
    return shouldHave;
  }
}

class SimNode {
  constructor(ownerDocument) {
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.childNodes = [];
    this._listeners = { capture: {}, bubble: {} };
  }

  get isConnected() {
    let cur = this;
    while (cur) {
      if (cur === this.ownerDocument || cur._isShadowRootConnected) return true;
      cur = cur.parentNode || cur.host || null;
    }
    return false;
  }

  get _isShadowRootConnected() {
    return Boolean(this.host && this.host.isConnected);
  }

  appendChild(child) {
    if (child.parentNode) {
      const idx = child.parentNode.childNodes.indexOf(child);
      if (idx !== -1) child.parentNode.childNodes.splice(idx, 1);
    }
    child.parentNode = this;
    this.childNodes.push(child);
    if (this.ownerDocument) this.ownerDocument._notifyMutation();
    return child;
  }

  append(...children) {
    for (const c of children) this.appendChild(c);
  }

  remove() {
    if (this.parentNode) {
      const idx = this.parentNode.childNodes.indexOf(this);
      if (idx !== -1) this.parentNode.childNodes.splice(idx, 1);
      this.parentNode = null;
      if (this.ownerDocument) this.ownerDocument._notifyMutation();
    }
  }

  replaceChildren(...nodes) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    for (const n of nodes) this.appendChild(n);
    if (this.ownerDocument) this.ownerDocument._notifyMutation();
  }

  contains(other) {
    let cur = other;
    while (cur) {
      if (cur === this) return true;
      cur = cur.parentNode;
    }
    return false;
  }

  addEventListener(type, fn, options) {
    const capture =
      typeof options === "boolean" ? options : Boolean(options && options.capture);
    const bucket = capture ? this._listeners.capture : this._listeners.bubble;
    if (!bucket[type]) bucket[type] = [];
    bucket[type].push(fn);
  }

  removeEventListener(type, fn, options) {
    const capture =
      typeof options === "boolean" ? options : Boolean(options && options.capture);
    const bucket = capture ? this._listeners.capture : this._listeners.bubble;
    if (!bucket[type]) return;
    bucket[type] = bucket[type].filter((item) => item !== fn);
  }

  dispatchEvent(event) {
    const innerTarget = this;
    const path = [];
    let cur = this;
    let shadowHost = null;

    while (cur) {
      path.push({ node: cur, inShadow: shadowHost === null });
      if (cur.host) {
        if (!event.composed) break;
        shadowHost = cur.host;
        cur = cur.host;
      } else {
        cur = cur.parentNode;
      }
    }

    if (this.ownerDocument && this.ownerDocument._window) {
      path.push({
        node: this.ownerDocument._window,
        inShadow: shadowHost === null,
      });
    }

    // Capture phase (window -> document -> ... -> target)
    // Note: in W3C DOM Events, an event listener registered on the target itself
    // with `capture: true` runs during the AT_TARGET phase, not before ancestors.
    for (let i = path.length - 1; i >= 0; i--) {
      const { node, inShadow } = path[i];
      event.target = inShadow || !shadowHost ? innerTarget : shadowHost;
      event.currentTarget = node;
      const list = (node._listeners.capture[event.type] || []).slice();
      for (const fn of list) {
        fn.call(node, event);
        if (event._immediateStopped) break;
      }
      if (event._stopped) return !event.defaultPrevented;
    }

    // Bubble phase (target -> ... -> document -> window)
    const maxIdx = event.bubbles ? path.length : 1;
    for (let i = 0; i < maxIdx; i++) {
      const { node, inShadow } = path[i];
      event.target = inShadow || !shadowHost ? innerTarget : shadowHost;
      event.currentTarget = node;
      const list = (node._listeners.bubble[event.type] || []).slice();
      for (const fn of list) {
        fn.call(node, event);
        if (event._immediateStopped) break;
      }
      if (event._stopped) break;
    }

    return !event.defaultPrevented;
  }

  querySelectorAll(selector) {
    const out = [];
    const visit = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === 1) {
          if (matchesSelector(child, selector)) out.push(child);
          visit(child);
        }
      }
    };
    visit(this);
    return out;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

class SimElement extends SimNode {
  constructor(tagName, ownerDocument) {
    super(ownerDocument);
    this.nodeType = 1;
    this.tagName = tagName.toUpperCase();
    this._attrs = new Map();
    this.style = { display: "" };
    this.classList = new SimClassList(this);
    this._text = "";
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.scrollHeight = 38;
    this.contentWindow = null;
  }

  get id() {
    return this._attrs.get("id") || "";
  }
  set id(v) {
    this._attrs.set("id", String(v));
  }

  get className() {
    return this._attrs.get("class") || "";
  }
  set className(v) {
    this._attrs.set("class", String(v));
  }

  get offsetParent() {
    if (this.style && this.style.display === "none") return null;
    return this.parentNode;
  }

  get nextElementSibling() {
    if (!this.parentNode) return null;
    const siblings = this.parentNode.childNodes;
    const idx = siblings.indexOf(this);
    return idx !== -1 && idx + 1 < siblings.length ? siblings[idx + 1] : null;
  }

  get textContent() {
    if (this.childNodes.length === 0) return this._text;
    return this._text + this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.childNodes = [];
    this._text = v === undefined || v === null ? "" : String(v);
    if (this.ownerDocument) this.ownerDocument._notifyMutation();
  }

  get innerText() {
    return this.textContent;
  }
  set innerText(v) {
    this.textContent = v;
  }

  get innerHTML() {
    return this.textContent;
  }
  set innerHTML(v) {
    if (v === "<p><br></p>" || v === "") {
      this.textContent = "";
    } else {
      this.textContent = v.replace(/<[^>]+>/g, "");
    }
  }

  setAttribute(name, val) {
    this._attrs.set(name, String(val));
  }
  getAttribute(name) {
    return this._attrs.has(name) ? this._attrs.get(name) : null;
  }
  hasAttribute(name) {
    return this._attrs.has(name);
  }
  removeAttribute(name) {
    this._attrs.delete(name);
  }

  insertAdjacentElement(position, el) {
    if (!this.parentNode) return null;
    if (el.parentNode) el.remove();
    const siblings = this.parentNode.childNodes;
    const idx = siblings.indexOf(this);
    el.parentNode = this.parentNode;
    if (position === "afterend") {
      siblings.splice(idx + 1, 0, el);
    } else if (position === "beforebegin") {
      siblings.splice(idx, 0, el);
    } else {
      this.appendChild(el);
    }
    if (this.ownerDocument) this.ownerDocument._notifyMutation();
    return el;
  }

  closest(selector) {
    let cur = this;
    while (cur && cur.nodeType === 1) {
      if (matchesSelector(cur, selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }

  attachShadow(_init) {
    const root = new SimNode(this.ownerDocument);
    root.host = this;
    root.adoptedStyleSheets = [];
    return root;
  }

  focus() {}

  click() {
    if (this.disabled) return;
    if (this.tagName === "INPUT" && this.getAttribute("type") === "checkbox") {
      this.checked = !this.checked;
      this.dispatchEvent(new SimEvent("change", { bubbles: true }));
    }
    this.dispatchEvent(new SimEvent("click", { bubbles: true, cancelable: true }));
  }
}

class SimDocument extends SimNode {
  constructor(ElementClass = SimElement) {
    super(null);
    this.ownerDocument = this;
    this._ElementClass = ElementClass;
    this.nodeType = 9;
    this.documentElement = new ElementClass("html", this);
    this.head = new ElementClass("head", this);
    this.body = new ElementClass("body", this);
    this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
    this.appendChild(this.documentElement);
    this._observers = [];
    this._mutationScheduled = false;
  }

  createElement(tag) {
    return new this._ElementClass(tag, this);
  }

  getElementById(id) {
    return this.querySelector("#" + id);
  }

  _notifyMutation() { if (global._traceMut) console.log("[MUT]", new Error().stack.split("\n").slice(1,4).join(" | "));
    if (this._mutationScheduled) return;
    this._mutationScheduled = true;
    queueMicrotask(() => {
      this._mutationScheduled = false;
      for (const obs of this._observers) {
        obs._callback([]);
      }
    });
  }
}

function parseSimpleHtmlIntoDocument(doc, html) {
  const cleaned = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<!DOCTYPE[^>]*>/gi, "");

  const bodyMatch = cleaned.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  const content = bodyMatch ? bodyMatch[1] : cleaned;

  const stack = [doc.body];
  const tagRegex = /<\/?([a-zA-Z0-9]+)([^>]*?)(\/?)>|([^<]+)/g;
  const voidTags = new Set(["input", "img", "br", "hr", "meta", "link", "polygon"]);

  let m;
  while ((m = tagRegex.exec(content)) !== null) {
    if (m[4] !== undefined) {
      const text = m[4];
      if (text.trim()) {
        const top = stack[stack.length - 1];
        top._text = (top._text || "") + text.replace(/\s+/g, " ");
      }
      continue;
    }
    const fullTag = m[0];
    const tagName = m[1].toLowerCase();
    const attrStr = m[2] || "";
    const selfClosing = Boolean(m[3]) || voidTags.has(tagName);

    if (fullTag.startsWith("</")) {
      if (stack.length > 1) stack.pop();
      continue;
    }

    if (tagName === "script") continue;

    const el = doc.createElement(tagName);
    const attrPattern = /([a-zA-Z0-9_-]+)(?:="([^"]*)")?/g;
    let am;
    while ((am = attrPattern.exec(attrStr)) !== null) {
      const k = am[1];
      const v = am[2] !== undefined ? am[2] : "";
      el.setAttribute(k, v);
      if (k === "hidden") el.hidden = true;
      if (k === "type") el.type = v;
    }

    stack[stack.length - 1].appendChild(el);
    if (!selfClosing) stack.push(el);
  }
}

class FallbackJSDOM {
  constructor(html = "", options = {}) {
    const parsedUrl = new URL(options.url || "https://www.instagram.com/");
    class WindowElement extends SimElement {}
    const doc = new SimDocument(WindowElement);
    parseSimpleHtmlIntoDocument(doc, html);

    class SimMutationObserver {
      constructor(cb) {
        this._callback = cb;
      }
      observe() {
        doc._observers.push(this);
      }
      disconnect() {}
    }

    const winNode = new SimNode(doc);

    const win = {
      _listeners: winNode._listeners,
      addEventListener: winNode.addEventListener.bind(winNode),
      removeEventListener: winNode.removeEventListener.bind(winNode),
      dispatchEvent: winNode.dispatchEvent.bind(winNode),
      postMessage(data, _targetOrigin) {
        queueMicrotask(() => {
          const evt = new SimEvent("message", { data });
          win.dispatchEvent(evt);
        });
      },
      document: doc,
      location: {
        href: parsedUrl.href,
        pathname: parsedUrl.pathname,
        hostname: parsedUrl.hostname,
        search: parsedUrl.search,
      },
      URL,
      URLSearchParams,
      Event: SimEvent,
      KeyboardEvent: SimKeyboardEvent,
      HTMLElement: WindowElement,
      Element: WindowElement,
      MutationObserver: SimMutationObserver,
      CSSStyleSheet: class {
        replaceSync() {}
      },
      TextEncoder,
      TextDecoder,
      Uint8Array,
      Int32Array,
      Array,
      Object,
      Map,
      Set,
      WeakMap,
      Promise,
      Error,
      RegExp,
      JSON,
      Math,
      Date,
      String,
      Number,
      Boolean,
      console,
      setTimeout,
      clearTimeout,
      btoa: (s) => Buffer.from(s, "binary").toString("base64"),
      atob: (b) => Buffer.from(b, "base64").toString("binary"),
      navigator: {
        clipboard: {
          writeText: async () => {},
        },
      },
    };
    doc._window = win;
    win.window = win;
    win.parent = options.parentWindow || win;
    win.globalThis = win;
    this.window = win;
    this._context = vm.createContext(win);
    win.eval = (code) => vm.runInContext(code, this._context);
  }

  static async fromFile(filePath, options = {}) {
    const html = fs.readFileSync(filePath, "utf8");
    const dom = new FallbackJSDOM(html, {
      url: options.url || "https://www.instagram.com/",
      parentWindow: options.parentWindow,
    });
    if (options.beforeParse) options.beforeParse(dom.window);

    const dir = require("node:path").dirname(filePath);
    const scriptRegex = /<script\s+src="([^"]+)"><\/script>/g;
    let m;
    while ((m = scriptRegex.exec(html)) !== null) {
      const scriptPath = require("node:path").resolve(dir, m[1]);
      const code = fs.readFileSync(scriptPath, "utf8");
      dom.window.eval(code);
    }
    setTimeout(() => {
      dom.window.document.dispatchEvent(new SimEvent("load"));
    }, 10);
    return dom;
  }
}

module.exports = {
  JSDOM: NativeJSDOM || FallbackJSDOM,
};
