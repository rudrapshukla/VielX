/**
 * src/styles.js — Purplish-Bluish Instagram-Inspired Theme for VeilX v5.0.
 *
 * PALETTE
 *   - Electric Indigo (`#6366f1`) -> Cosmic Violet (`#8b5cf6`) -> Royal Blue (`#3b82f6`)
 *   - Deep Midnight Indigo-Slate (`#0f111c`)
 *   - Soft Lavender Mist (`#c7d2fe`)
 */

globalThis.GPV = globalThis.GPV || {};

GPV.styles = {
  css: `
    :host { all: initial; }
    * {
      box-sizing: border-box;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    [hidden] { display: none !important; }

    /* ── 1. Encrypted / Decrypted Message Bubble ────────────────────── */
    .bubble {
      display: flex;
      flex-direction: column;
      gap: 5px;
      min-width: 140px;
      max-width: 360px;
      color: inherit;
      font: inherit;
      padding: 2px 0;
    }

    .status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.15px;
      opacity: 0.85;
    }

    .status.ok {
      opacity: 0.95;
      color: inherit;
    }
    .status.error {
      opacity: 1;
      color: #f87171;
    }

    .pq-pill {
      display: inline-flex;
      align-items: center;
      padding: 1px 6px;
      border-radius: 999px;
      font-size: 9.5px;
      font-weight: 700;
      letter-spacing: 0.3px;
      background: color-mix(in srgb, currentColor 15%, transparent);
      color: inherit;
      border: 1px solid color-mix(in srgb, currentColor 28%, transparent);
    }

    .button {
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid color-mix(in srgb, currentColor 32%, transparent);
      background: color-mix(in srgb, currentColor 10%, transparent);
      color: inherit;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    .button:hover:not(:disabled) {
      background: color-mix(in srgb, currentColor 20%, transparent);
    }
    .button:focus-visible { outline: 2px solid #8b5cf6; outline-offset: 2px; }
    .button:disabled { opacity: 0.45; cursor: default; }

    .plain {
      font-size: 14px;
      line-height: 1.48;
      white-space: pre-wrap;
      word-break: break-word;
    }

    /* ── 2. Extension Origin Iframe Wrapper ─────────────────────────── */
    .vx-iframe-wrap {
      width: 100%;
      display: block;
    }
    .vx-composer-iframe {
      width: 100%;
      height: 54px;
      border: 0;
      background: transparent;
      display: block;
    }

    /* ── 3. Fallback / Test Pill Composer ───────────────────────────── */
    .vx-composer-shell {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      min-height: 44px;
      padding: 5px 6px 5px 8px;
      border-radius: 24px;
      background: #0f111c;
      border: 1.5px solid rgba(139, 92, 246, 0.28);
      box-shadow: 0 4px 20px rgba(10, 12, 24, 0.45);
      color: #f5f6fa;
    }

    .vx-chip-btn {
      height: 30px;
      padding: 0 11px;
      border-radius: 999px;
      border: 1px solid rgba(139, 92, 246, 0.35);
      background: rgba(99, 102, 241, 0.16);
      color: #c7d2fe;
      font-size: 11.5px;
      font-weight: 600;
      cursor: pointer;
    }

    .vx-textarea {
      flex: 1;
      min-height: 22px;
      max-height: 96px;
      padding: 4px 6px;
      border: 0;
      background: transparent;
      color: #f5f6fa;
      font-size: 14px;
      line-height: 1.42;
      resize: none;
    }
    .vx-textarea:focus { outline: none; }

    .vx-send-btn {
      height: 32px;
      padding: 0 16px;
      border-radius: 999px;
      border: 0;
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 52%, #3b82f6 100%);
      color: #ffffff;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
    }

    .vx-counter {
      font-size: 11px;
      color: #7c809b;
      padding: 0 4px;
    }

    /* ── 4. Floating Notice (Toast) ─────────────────────────────────── */
    .toast {
      display: flex;
      align-items: center;
      gap: 12px;
      max-width: min(460px, 92vw);
      padding: 11px 16px;
      border-radius: 999px;
      border: 1px solid rgba(139, 92, 246, 0.35);
      background: rgba(15, 17, 28, 0.95);
      backdrop-filter: blur(16px);
      color: #f5f6fa;
      font: 12.5px/1.4 -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
      box-shadow: 0 12px 36px rgba(10, 12, 28, 0.6);
    }
    .toast.info    { border-color: rgba(139, 92, 246, 0.45); }
    .toast.error   { border-color: rgba(248, 113, 113, 0.5); }
    .toast.warning { border-color: rgba(245, 158, 11, 0.5); }

    .toast-text { flex: 1; padding-left: 4px; }

    .toast-action,
    .toast-close {
      border: 1px solid rgba(139, 92, 246, 0.35);
      background: rgba(99, 102, 241, 0.18);
      color: #e0e7ff;
      border-radius: 999px;
      padding: 5px 13px;
      font: 600 11.5px -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
      cursor: pointer;
    }
    .toast-action {
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 52%, #3b82f6 100%);
      border-color: transparent;
      color: #ffffff;
    }
    .toast-action:hover { filter: brightness(1.1); }
    .toast-close { padding: 5px 9px; background: transparent; border-color: transparent; color: #9da2c0; }
    .toast-close:hover { color: #ffffff; }
  `,

  /**
   * Page-level Purplish-Bluish Instagram UI Theme.
   */
  pageThemeCss: `
    [data-veilx-hidden-composer="1"] {
      position: fixed !important;
      left: -99999px !important;
      top: -99999px !important;
      width: 1px !important;
      height: 1px !important;
      opacity: 0 !important;
      pointer-events: none !important;
      overflow: hidden !important;
      z-index: -1 !important;
    }

    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-track {
      background: transparent;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-thumb {
      background: linear-gradient(180deg, rgba(99, 102, 241, 0.45), rgba(139, 92, 246, 0.45));
      border-radius: 999px;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-thumb:hover {
      background: linear-gradient(180deg, rgba(99, 102, 241, 0.75), rgba(139, 92, 246, 0.75));
    }

    html[data-veilx-ui="beautiful"] [role="main"] {
      background: radial-gradient(circle at top right, rgba(99, 102, 241, 0.08), transparent 55%),
                  radial-gradient(circle at bottom left, rgba(139, 92, 246, 0.06), transparent 50%) !important;
    }

    html[data-veilx-ui="beautiful"] span[data-gpv-host="1"] {
      display: inline-block;
      vertical-align: middle;
    }

    div[data-gpv-composer-host="1"] {
      display: block;
      width: 100%;
      padding: 6px 14px 12px 14px;
      box-sizing: border-box;
      z-index: 20;
    }
  `,
};

if (typeof module !== "undefined") module.exports = GPV.styles;
