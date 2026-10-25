# Threat Model — VeilX v5.2.0

This document defines the security guarantees, active cryptographic and browser-isolation defenses, and threat-model boundaries of **VeilX v5.2.0**.

## 1. Active Security Defenses

| Threat Vector | Defense in VeilX v5.2.0 | Implementation |
| :--- | :--- | :--- |
| **Host-page keystroke harvesting (`keydown`, `beforeinput`, `input`, `paste`)** | Message composition runs inside a cross-origin **`chrome-extension://` `<iframe>`** (`composer/composer.html`). Under browser Site Isolation and Same-Origin Policy, typing events never enter Instagram's DOM or `window` capture listeners. | `composer/composer.html`, `composer/composer.js`, `src/ui.js` |
| **Host-page `window.postMessage` bridge sniffing** | In-frame encryption produces `GPV2:...` ciphertexts inside `composer/composer.js` and routes them strictly over privileged **`chrome.runtime.sendMessage`** through the MV3 Service Worker (`src/background.js`) to `src/content.js`. Zero `window.postMessage` calls exist. | `composer/composer.js`, `src/background.js`, `src/content.js` |
| **Quantum & Classical Eavesdropping ("Harvest Now, Decrypt Later")** | Hybrid key exchange combining **NIST FIPS 203 ML-KEM-768** (`k=3, n=256, q=3329`, FIPS 202 `SHA3-256`/`SHA3-512`/`SHAKE128`/`SHAKE256`, Fujisaki-Okamoto implicit rejection) with classical **NIST P-256 ECDH** via **HKDF-SHA256**. | `src/crypto.js` |
| **Past Message Exposure After Future Key Compromise** | Destructive one-way **HMAC-SHA256 Chain Ratchet** (`ratchetChainStep` / `advanceConversationRatchet`) derives per-message keys and overwrites the previous chain key in storage. | `src/crypto.js`, `src/store.js` |
| **Message Tampering, Length Fingerprinting & Replay** | Every message is encrypted with **AES-256-GCM** (96-bit random IV, 128-bit GHASH authentication tag), padded to 32-byte blocks via **ISO/IEC 7816-4**, and tracked via live DOM element references (`activeTokenElements`) to block duplicate replay bubbles while allowing React virtual-scroller re-renders. | `src/crypto.js`, `src/content.js` |
| **Active Man-in-the-Middle (MITM) Key Substitution** | Computes an **80-bit SHA-256 Safety Code** over sorted hybrid public key bundles so peers can verify authenticity out-of-band and optionally enforce verification before sending. | `src/crypto.js`, `popup/popup.js`, `app/app.js` |
| **At-Rest Local Profile Inspection** | **Master Key Vault** (`lockVault` / `unlockVault`) seals `identity` and all `conv:*` records using **PBKDF2-HMAC-SHA256** (600,000 iterations, 128-bit salt) + **AES-256-GCM** and removes plaintext keys from `chrome.storage.local`. | `src/crypto.js`, `src/store.js`, `popup/popup.js`, `app/app.js` |

## 2. Threat-Model Boundaries & Limitations

* **Compromised Endpoint, OS, or Browser Binary:** VeilX operates within the browser extension security boundary. It cannot protect secrets against local OS malware, hardware keyloggers, or a compromised browser process while the Vault is unlocked.
* **Rendered Decrypted Bubbles:** Decrypted messages are rendered inside closed Shadow DOM roots (`attachShadow({ mode: "closed" })`) to prevent `document.querySelectorAll` traversal by page scripts, while relying on Instagram's transport layer for ciphertext delivery.
* **Native Media Attachments & Metadata:** Photos, videos, voice notes, and reactions sent through Instagram's native media controls are not encrypted by VeilX, and conversation metadata (participants and timestamps) remains visible to Instagram.
