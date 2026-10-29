/**
 * src/styles.js — Obsidian Midnight Black & Titanium Theme for VeilX.
 *
 * Matches the palette of veilxweb.onrender.com:
 *   - Midnight / Obsidian Background (#000000, #050608, #08090c, #0e1015)
 *   - Titanium Surface & Specular Hairlines (#171b22, rgba(255, 255, 255, 0.09))
 *   - Crisp White (#ffffff) & Zinc (#e4e4e7, #a1a1aa) typography
 */

globalThis.VX = globalThis.VX || {};

VX.styles = {
  css: `
    :host { all: initial; }
    * {
      box-sizing: border-box;
      font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    [hidden] { display: none !important; }

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
      flex-wrap: wrap;
      gap: 6px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.15px;
      opacity: 0.88;
    }

    .status.ok {
      opacity: 0.96;
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
      border-radius: 6px;
      font-family: "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace;
      font-size: 9.5px;
      font-weight: 600;
      letter-spacing: 0.25px;
      background: color-mix(in srgb, currentColor 12%, transparent);
      color: inherit;
      border: 1px solid color-mix(in srgb, currentColor 24%, transparent);
    }

    .button {
      padding: 6px 12px;
      border-radius: 10px;
      border: 1px solid color-mix(in srgb, currentColor 28%, transparent);
      background: color-mix(in srgb, currentColor 10%, transparent);
      color: inherit;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s ease;
    }
    .button:hover:not(:disabled) {
      background: color-mix(in srgb, currentColor 18%, transparent);
    }
    .button:focus-visible { outline: 2px solid #ffffff; outline-offset: 2px; }
    .button:disabled { opacity: 0.45; cursor: default; }

    .plain {
      font-size: 14px;
      line-height: 1.48;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .vx-img-wrap,
    .vx-video-wrap {
      margin-top: 4px;
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: #07080a;
      max-width: 340px;
      transition: max-width 0.2s ease;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.55);
    }
    .vx-img-wrap.expanded {
      max-width: min(640px, 78vw);
    }
    .vx-img {
      display: block;
      width: 100%;
      height: auto;
      max-height: 380px;
      object-fit: contain;
      cursor: zoom-in;
      border-radius: 13px;
    }
    .vx-img-wrap.expanded .vx-img {
      max-height: 75vh;
      cursor: zoom-out;
    }
    .vx-video {
      display: block;
      width: 100%;
      max-height: 360px;
      border-radius: 13px;
      background: #000000;
    }
    .vx-audio-wrap {
      margin-top: 4px;
      padding: 6px 8px;
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: #0b0d11;
      min-width: 240px;
      max-width: 320px;
    }
    .vx-audio {
      display: block;
      width: 100%;
      height: 36px;
    }
    .vx-img-actions {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-top: 3px;
      font-size: 11px;
      opacity: 0.9;
    }
    .vx-img-dl {
      color: inherit;
      text-decoration: none;
      font-weight: 600;
      padding: 2px 9px;
      border-radius: 8px;
      background: color-mix(in srgb, currentColor 12%, transparent);
      border: 1px solid color-mix(in srgb, currentColor 24%, transparent);
    }
    .vx-img-dl:hover {
      background: color-mix(in srgb, currentColor 22%, transparent);
    }
    .vx-img-meta {
      font-family: "JetBrains Mono", ui-monospace, monospace;
      font-size: 10.5px;
      opacity: 0.75;
    }
    .vx-progress-pill {
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 12px;
      padding: 8px 11px;
      border-radius: 12px;
      background: rgba(11, 13, 17, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.14);
      min-width: 210px;
    }
    .vx-progress-label {
      font-weight: 500;
    }
    .vx-progress-track {
      width: 100%;
      height: 4px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.12);
      overflow: hidden;
    }
    .vx-progress-fill {
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, #a1a1aa 0%, #ffffff 55%, #34d399 100%);
      transition: width 0.18s ease-out;
    }

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

    .vx-composer-shell {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      min-height: 44px;
      padding: 5px 6px 5px 8px;
      border-radius: 22px;
      background: #08090c;
      border: 1px solid rgba(255, 255, 255, 0.12);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.75);
      color: #f8fafc;
    }

    .vx-chip-btn {
      height: 30px;
      padding: 0 11px;
      border-radius: 11px;
      border: 1px solid rgba(255, 255, 255, 0.12);
      background: rgba(255, 255, 255, 0.06);
      color: #e4e4e7;
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
      color: #f8fafc;
      font-size: 14px;
      line-height: 1.42;
      resize: none;
    }
    .vx-textarea:focus { outline: none; }

    .vx-send-btn {
      height: 32px;
      padding: 0 16px;
      border-radius: 12px;
      border: 0;
      background: #ffffff;
      color: #000000;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
    }

    .vx-counter {
      font-size: 11px;
      color: #71717a;
      padding: 0 4px;
    }

    .toast {
      display: flex;
      align-items: center;
      gap: 12px;
      max-width: min(460px, 92vw);
      padding: 11px 16px;
      border-radius: 16px;
      border: 1px solid rgba(255, 255, 255, 0.14);
      background: linear-gradient(180deg, rgba(22, 26, 34, 0.96) 0%, rgba(10, 12, 16, 0.98) 100%);
      backdrop-filter: blur(16px);
      color: #f8fafc;
      font: 12.5px/1.4 "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 16px 40px rgba(0, 0, 0, 0.85);
    }
    .toast.info    { border-color: rgba(255, 255, 255, 0.16); }
    .toast.error   { border-color: rgba(248, 113, 113, 0.5); }
    .toast.warning { border-color: rgba(245, 158, 11, 0.5); }

    .toast-text { flex: 1; padding-left: 4px; }

    .toast-action,
    .toast-close {
      border: 1px solid rgba(255, 255, 255, 0.14);
      background: #141822;
      color: #f8fafc;
      border-radius: 10px;
      padding: 5px 13px;
      font: 600 11.5px "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
      cursor: pointer;
    }
    .toast-action {
      background: #ffffff;
      border-color: #ffffff;
      color: #000000;
    }
    .toast-action:hover { background: #e4e4e7; }
    .toast-close { padding: 5px 9px; background: transparent; border-color: transparent; color: #a1a1aa; }
    .toast-close:hover { color: #ffffff; }
  `,

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

    [data-vx-collapsed-chunk="1"] {
      display: none !important;
    }

    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar {
      width: 4px;
      height: 4px;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-track {
      background: transparent;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.16);
      border-radius: 999px;
    }
    html[data-veilx-ui="beautiful"] ::-webkit-scrollbar-thumb:hover {
      background: rgba(255, 255, 255, 0.30);
    }

    html[data-veilx-ui="beautiful"] [role="main"] {
      background-color: #050608 !important;
      background-image:
        radial-gradient(circle at 50% 0%, rgba(255, 255, 255, 0.035) 0%, transparent 55%),
        linear-gradient(180deg, #08090c 0%, #040507 100%) !important;
    }

    html[data-veilx-ui="beautiful"] span[data-vx-host="1"] {
      display: inline-block;
      vertical-align: middle;
    }

    div[data-vx-composer-host="1"] {
      display: block;
      width: 100%;
      padding: 6px 14px 12px 14px;
      box-sizing: border-box;
      z-index: 20;
    }
  `,
};

if (typeof module !== "undefined") module.exports = VX.styles;
