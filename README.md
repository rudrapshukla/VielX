# VeilX v5.2.0 — Post-Quantum End-to-End Encryption & Studio for Instagram Direct

**VeilX** is a zero-dependency Chrome Manifest V3 extension that brings client-side, post-quantum hybrid authenticated encryption (**NIST FIPS 203 ML-KEM-768 + ECDH P-256 + AES-256-GCM**) to Instagram Direct Messages while isolating message composition inside a cross-origin `chrome-extension://` sandbox so the host webpage can never inspect your keystrokes or plaintext.

> *असतो मा सद्गमय*
> *Lead me from falsehood to truth.*
> — Bṛhadāraṇyaka Upaniṣad, 1.3.28

![VeilX Preview](thumbnail.png)

## Key Capabilities

* **Cross-Origin Keystroke & Plaintext Isolation:** Replaces Instagram's native Lexical input box with a dedicated `chrome-extension://` iframe pill composer (`composer/composer.html`). Typing events (`keydown`, `beforeinput`, `input`, `paste`) fire strictly inside the extension's isolated browsing context and never enter Instagram's DOM or `window` capture listeners.
* **Zero-`postMessage` Privileged IPC Broker:** Encryption happens inside the composer iframe before any data leaves the frame. Only finished `GPV2:...` ciphertexts traverse `chrome.runtime.sendMessage` through the extension Service Worker (`src/background.js`) to the content script (`src/content.js`).
* **Standardized Post-Quantum Hybrid Key Exchange:** Combines **NIST FIPS 203 ML-KEM-768** (`k=3, n=256, q=3329`, 32-bit interleaved **FIPS 202 Keccak-f[1600]**, Number-Theoretic Transform, and Fujisaki-Okamoto implicit rejection) with classical **NIST P-256 ECDH** via `HKDF-SHA256`.
* **Automatic Multi-Packet Wire Framing:** Splits 1,249-byte hybrid public keys and 1,088-byte ML-KEM-768 capsules into compact `< 880`-character `GPV2K:P1/N#<bundleId>#...` packets that fit cleanly within Instagram Direct's 1,000-character message limit and reassemble automatically on arrival.
* **Destructive Forward-Secrecy Symmetric Chain Ratchet:** Advances a 256-bit conversation chain key via one-way `HMAC-SHA256` steps (`ratchetChainStep`) and overwrites previous chain keys on disk so future storage compromise cannot recover past message keys.
* **AES-256-GCM Envelopes & Traffic-Analysis Padding:** Encrypts every message with a fresh 96-bit random IV, 128-bit authentication tag, monotonic sequence numbers, multi-part message chunking, and 32-byte **ISO/IEC 7816-4** block padding (`0x80 0x00...`) to mask exact character lengths of short messages.
* **Master Key Vault at Rest:** Seals all conversation keys and identity private keys in `chrome.storage.local` under a master passphrase using **PBKDF2-HMAC-SHA256** (600,000 iterations, 128-bit random salt) and **AES-256-GCM**.
* **VeilX Studio Standalone Web App:** Includes a full-window split-screen workspace (`app/app.html`) that embeds Instagram Direct alongside a dedicated Quantum Security Command Deck using `declarativeNetRequest` session rules.
* **Zero Third-Party Runtime Dependencies:** Ships 100% self-contained JavaScript at runtime with zero external `npm` packages, eliminating supply-chain key exfiltration risks.

## Cryptographic & Architectural Specification

| Component | Standard / Primitive | Implementation Details |
| :--- | :--- | :--- |
| **Post-Quantum KEM** | NIST FIPS 203 ML-KEM-768 | Module-LWE (`k=3, n=256, q=3329, eta1=2, eta2=2, du=10, dv=4`), 1,184-byte `ek`, 2,400-byte `dk`, 1,088-byte ciphertext `c`, FO implicit rejection |
| **Sponge & XOF Hash** | NIST FIPS 202 Keccak-f[1600] | 32-bit lane-interleaved `Uint32Array` state powering `SHA3-256`, `SHA3-512`, `SHAKE128`, and `SHAKE256` |
| **Classical Key Agreement** | WebCrypto ECDH P-256 | 65-byte uncompressed NIST P-256 public point combined with ML-KEM-768 (`1,249-byte` hybrid public bundle) |
| **Hybrid Key Derivation** | WebCrypto HKDF-SHA256 | Extracts & expands concatenated 32-byte ECDH secret + 32-byte ML-KEM-768 secret with sorted public-key salt |
| **Symmetric Encryption** | WebCrypto AES-256-GCM | 256-bit key, 96-bit CSPRNG IV per message, 128-bit GHASH authentication tag, ISO/IEC 7816-4 32-byte block padding |
| **Forward-Secrecy Ratchet** | WebCrypto HMAC-SHA256 | One-way PRF deriving `MK_n = HMAC(CK_n, 0x01)` and `CK_{n+1} = HMAC(CK_n, 0x02)` with destructive key overwrite |
| **Passphrase & Vault KDF** | WebCrypto PBKDF2-SHA256 | 600,000 iterations, NFKC normalization, 100-bit 20-character base-32 passphrase generator (`XXXX-XXXX-XXXX-XXXX`) |
| **MITM Verification** | 80-bit SHA-256 Safety Code | Five 4-hex-character blocks (`A1B2 C3D4 E5F6 7788 99AA`) computed over sorted hybrid public key bundles |

## System Architecture & Execution Contexts

VeilX v5.2.0 partitions execution across five browser contexts to enforce strict privilege separation:

1. **Extension Composer Iframe (`composer/composer.html`, `composer.js`, `composer.css`):**
   Runs inside a `chrome-extension://` origin mounted in the Instagram chat footer. Captures user input in an isolated window, splits long messages into UTF-8 chunks, encrypts each chunk with `AES-256-GCM`, and dispatches only `GPV2:...` ciphertexts over `chrome.runtime.sendMessage`.
2. **MV3 Service Worker Broker (`src/background.js`):**
   Relays privileged `GPV_BROKER_SEND_CIPHERTEXT` and `GPV_BROKER_SEND_KEY` commands between the composer iframe and the active tab's content script via `chrome.tabs.sendMessage`, and configures `declarativeNetRequest` session rules (`5001`–`5004`) so VeilX Studio can embed Instagram Direct with full WebSocket/MQTT and GraphQL functionality.
3. **Content Script Conductor (`src/content.js`, `src/dom.js`, `src/ui.js`, `src/styles.js`):**
   Executes in Chrome's Isolated World on `instagram.com`. Hides Instagram's native Lexical textbox off-screen while keeping its React Fiber node mounted, atomically writes `GPV2:...` ciphertexts into the hidden editor on send, reassembles multi-packet `GPV2K:` handshakes, and renders decrypted messages inside closed Shadow DOM roots (`attachShadow({ mode: "closed" })`).
4. **Popup Control Center (`popup/popup.html`, `popup.js`, `popup.css`):**
   Centralizes all conversation security controls, master encryption toggles, 100-bit passphrase generation, ML-KEM-768 key exchange initiation, 80-bit Safety Code verification, Master Key Vault locking/unlocking, and the **Open VeilX Studio** launcher.
5. **VeilX Studio Standalone Web App (`app/app.html`, `app.js`, `app.css`):**
   A full-page extension workspace providing a persistent Quantum Security Command Deck on the left and a live embedded Instagram Direct client on the right.

## Installation

1. Clone or download this repository to your machine:
   ```bash
   git clone https://github.com/rudrapshukla/guptavarta.git
   cd guptavarta
   ```
2. Open Google Chrome (or any Chromium-based browser, version 111+) and navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click **Load unpacked** in the top-left corner and select the root folder of this repository (the folder containing `manifest.json`).
5. Pin **VeilX** to your browser toolbar and open `https://www.instagram.com/direct/inbox/`.

## How to Use

### Method 1: Post-Quantum Hybrid Key Exchange (Recommended)
1. Open an Instagram Direct conversation with a contact who also has VeilX installed.
2. Click **Exchange Key** in the on-page VeilX chat bar (or open the VeilX toolbar popup, select **Key Exchange**, and click **Send my key into chat**).
3. VeilX sends your 1,249-byte **ML-KEM-768 + P-256** public key as compact `GPV2K:` packets.
4. When your contact clicks **Accept PQ Key** / **Send my key**, their extension encapsulates a 256-bit ML-KEM-768 secret and replies with their hybrid capsule.
5. Both sides automatically derive the shared 256-bit **AES-256-GCM** key. Optional: open the VeilX popup to compare the **80-bit Safety Code** with your contact and click **Verify safety code**.
6. Type in the Purplish-Bluish VeilX pill composer and press **Enter** or **Send**.

### Method 2: Shared 100-Bit Passphrase
1. Open an Instagram Direct conversation and click the **VeilX** toolbar icon.
2. Under the **Shared Passphrase** tab, click **Generate** to create a 100-bit cryptographic passphrase (or enter your own 12+ character passphrase), click **Copy**, and share it with your contact over a trusted channel.
3. Click **Save Key**. Both you and your contact can immediately send and receive encrypted messages in the chat.

### Using VeilX Studio & Master Key Vault
* **VeilX Studio:** Click **Open VeilX Studio ↗** at the top of the VeilX popup to open the standalone split-screen web app (`app/app.html`).
* **Master Key Vault:** In the popup or Studio sidebar, enter a 12+ character master passphrase under **Master Key Vault** and click **Lock Vault** when stepping away from your device. All stored conversation keys and private keys are encrypted into a single `AES-256-GCM` vault blob and wiped from plaintext storage until unlocked.

## Project Structure

```text
├── manifest.json             # Chrome Manifest V3 configuration & CSP
├── package.json              # Project metadata & Node test script
├── src/
│   ├── background.js         # MV3 Service Worker IPC broker & declarativeNetRequest rules
│   ├── crypto.js             # FIPS 202 Keccak, FIPS 203 ML-KEM-768, ECDH P-256, HKDF, HMAC ratchet, AES-256-GCM, Vault
│   ├── store.js              # chrome.storage.local state manager, key history & Vault operations
│   ├── util.js               # URL thread-ID parser, UTF-8 byte counter & multi-chunk splitter
│   ├── dom.js                # Scoped Instagram DOM selectors, sidebar filter & atomic Lexical writer
│   ├── ui.js                 # Closed Shadow DOM factory, encrypted bubble renderer & iframe mounter
│   ├── styles.js             # Purplish-Bluish Electric Indigo & Violet themes for Shadow DOM & Instagram UI
│   └── content.js            # Content script conductor, multi-packet KEM handshake & live-DOM replay guard
├── composer/
│   ├── composer.html         # Cross-origin extension composer iframe markup
│   ├── composer.css          # Single-line Purplish-Bluish pill composer styling
│   └── composer.js           # In-frame AES-256-GCM encryption & chrome.runtime IPC sender
├── popup/
│   ├── popup.html            # Toolbar Control Center markup
│   ├── popup.css             # Popup stylesheet
│   └── popup.js              # Passphrase, ML-KEM-768 handshake, Safety Code & Vault controller
├── app/
│   ├── app.html              # VeilX Studio standalone split-screen web app markup
│   ├── app.css               # VeilX Studio stylesheet
│   └── app.js                # VeilX Studio controller
├── tests/
│   ├── dom_harness.js        # Zero-dependency W3C Shadow DOM, composed event & iframe simulator
│   ├── crypto.test.js        # Cryptographic unit tests (ML-KEM-768, FO rejection, ratchet, padding, Vault)
│   ├── content.smoke.test.js # End-to-end DOM, cross-origin iframe isolation & handshake integration tests
│   └── popup.smoke.test.js   # Popup Control Center & Vault UI integration tests
└── docs/
    └── THREAT_MODEL.md       # Formal security boundaries and threat model
```

## Running the Automated Test Suite

VeilX uses Node.js's built-in test runner (`node:test` and `node:assert`) and WebCrypto API (`node:crypto`) with zero external packages required:

```bash
npm test
# or run directly with Node.js (v18+):
node --test tests/crypto.test.js tests/popup.smoke.test.js tests/content.smoke.test.js
```

The 46-test suite verifies:
* **NIST FIPS 203 ML-KEM-768 & ECDH P-256 Hybrid KEM:** Key generation, encapsulation, decapsulation, Fujisaki-Okamoto implicit rejection of tampered ciphertexts, and multi-packet `< 1,000`-character wire framing.
* **Cross-Origin Composer Isolation:** Confirms zero `keydown`, `beforeinput`, or `window.postMessage` events leak to Instagram's `window` or `document` capture listeners during typing and sending.
* **Symmetric Cryptography & Ratcheting:** `AES-256-GCM` encryption/decryption, 32-byte ISO/IEC 7816-4 traffic-analysis padding, authenticated envelopes, destructive `HMAC-SHA256` chain ratcheting, and `PBKDF2-SHA256` (600,000 iterations) key derivation.
* **Live-DOM Replay & Virtual-Scroller Safety:** Verifies that React virtual-scroller re-renders, sidebar previews, and simultaneous multi-device handshakes decrypt cleanly while genuine duplicate replay bubbles are blocked.
* **Master Key Vault:** Verifies full at-rest encryption and restoration of keys in `chrome.storage.local`.

## Security Threat Model & Boundaries

* **Protected Against:**
  * Host-page keystroke harvesting (`keydown` / `beforeinput` / `input` capture listeners on `instagram.com`).
  * Host-page `window.addEventListener("message")` bridge sniffing (zero `window.postMessage` traffic).
  * Host-page DOM scraping of decrypted messages (`attachShadow({ mode: "closed" })`).
  * Classical and future quantum passive eavesdropping (*"Harvest Now, Decrypt Later"*) via hybrid **NIST FIPS 203 ML-KEM-768 + ECDH P-256** and **AES-256-GCM**.
  * Active key substitution when users verify the **80-bit Safety Code** out-of-band.
  * Unencrypted disk inspection when the **Master Key Vault** is locked.
* **Out of Scope / Limitations:**
  * Media attachments (photos, videos, voice notes) sent through Instagram's native media uploaders are not encrypted by VeilX.
  * Conversation metadata (participants, message timestamps, and approximate packet count) remains visible to Instagram's servers.
  * Like any browser extension, VeilX cannot protect secrets against a compromised operating system, malicious root/admin processes, or a compromised browser binary while the vault is unlocked.

## License & Credits

Created by **Team Monolith** ([Rudra Pratap Shukla](https://github.com/rudrapshukla)). Released under the [MIT License](LICENSE).
