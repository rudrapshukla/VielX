# VeilX 1.1.0 — Post-Quantum End-to-End Encrypted Text, Original-Quality Images, Short Videos & Voice Notes for Instagram Direct

VeilX is a Chrome (Manifest V3) extension that adds end-to-end encryption on top of Instagram Direct messages. Messages, original-quality images, short videos, and voice notes are encrypted inside an isolated extension-origin iframe so only ciphertext (`VX1:…`) ever reaches Instagram.

## What it does

* **Hybrid post-quantum key exchange:** ML-KEM-768 (FIPS 203) + ephemeral ECDH P-256. An attacker must break both.
* **Forward secrecy:** fresh ephemeral keys per exchange, no long-term identity key, per-direction hash-ratchet chains with message keys used once and deleted.
* **Authenticated everything:** AES-256-GCM with header, direction, sequence number and conversation id bound as AAD. Replays, reflections, reordering and cross-chat splicing are detected.
* **Verification by default:** a 128-bit safety code covers the whole handshake transcript; sending is blocked until you confirm it with your contact.
* **Original-fidelity encrypted media sidecars (1 DM):** attaches or drops original-quality images (`image/png`, `image/jpeg`, `image/webp`, `image/gif`), short videos (`video/mp4`, `video/webm`, `video/quicktime`), and audio/voice notes (`audio/*` or live `🎙 Voice` recordings up to 15 MB). The **Sidecar Relay path bypasses `<canvas>` resizing and re-encoding completely**, encrypting the original file bytes bit-for-bit (`VX1B\x01` + fresh 256-bit AES-256-GCM key + 96-bit IV + MIME AAD) and sending **only 1 compact `VX1:` pointer DM** over Instagram Direct.
* **Offline in-band fallback (images):** if the relay is unreachable, images can fall back to multi-chunk in-band `VX1:` messages (resized to fit Instagram's message rate limits).
* **Least-privilege host permissions:** `manifest.json` grants access strictly to Instagram/Facebook domains (`https://www.instagram.com/*`, `https://*.instagram.com/*`, `https://*.facebook.com/*`), the configured Cloudflare Worker relay (`https://veilx-relay.therealrudrashukla.workers.dev/*`), and local loopback (`http://127.0.0.1/*`, `http://localhost/*`) — never wildcard `https://*/*`.
* **Fail-closed composer:** you type and attach media in an extension-origin iframe. Typing in Instagram's own box is blocked, never sent.
* **Key Vault** (encrypt stored keys + history under a passphrase while away) and a direct launcher for the standalone **VeilX Web Messenger** (`https://veilxweb.onrender.com`).
* **Passphrase mode** for a quick shared secret — generated 100-bit passphrases only, and clearly labelled *no forward secrecy*.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for exactly what is and is not protected, including the public prototype relay abuse-control model. In short: post-quantum crypto does not authenticate anyone — **compare the safety code**.

## Protocol (summary)

```
Initiator → Responder   OFFER = ecPubI(65) ‖ mlkemEk(1184)
Responder → Initiator   REPLY = ecPubR(65) ‖ mlkemCt(1088) ‖ H(OFFER)[0:16]
TH   = SHA-256("veilx-v1-transcript" ‖ OFFER ‖ ecPubR ‖ mlkemCt)
root = HKDF-SHA256(ECDH(ephI,ephR) ‖ mlkemSS, salt = TH, info = "veilx-v1-root")
→ conversation id, two sender ids, two chain keys, safety code (all HKDF from root);
  ephemeral private keys and the root are then discarded.
message i:  mk = HMAC(ck, 0x01);  ck' = HMAC(ck, 0x02)
wire:       "VX1:" ‖ b64( 0x01 ‖ sid(8) ‖ seq(4) ‖ iv(12) ‖ AES-256-GCM(padded JSON) )
AAD:        "veilx-v1-msg" ‖ header ‖ conversationId

Media Sidecar (VX1B):
envelope:   "VX1B\x01"(5) ‖ iv(12) ‖ AES-256-GCM_k(originalFileBytes, AAD="veilx-v1-media:" ‖ mimeType)
chat DM:    1 forward-secret VX1: message carrying { t: "img_ref", u: blobUrl, k: keyB64, h: sha256(envelope), mt: mimeType, sz: byteLen }
```

## Installation

1. Download or extract this archive.
2. In Chrome (111+), open `chrome://extensions/` and enable **Developer mode**.
3. Click **Load unpacked** and select the `VeilX` folder that contains `manifest.json`.
4. Pin **VeilX** and open `https://www.instagram.com/direct/inbox/`.

## Deploying Your Own Zero-Knowledge Relay (`server/`)

The extension defaults to the hosted public prototype relay (`https://veilx-relay.therealrudrashukla.workers.dev`). To deploy your own Cloudflare Worker or run the local loopback relay:

```powershell
cd server
# Mode A: Zero-R2 Free Tier (Cloudflare Edge Cache + Isolate Memory with 5-read burn enforcement)
npx.cmd wrangler deploy worker.js --config wrangler.toml

# Mode B: Durable Cloudflare R2 Storage (Optional)
npx.cmd wrangler r2 bucket create veilx-encrypted-media
npx.cmd wrangler deploy worker.js --config wrangler.toml --env r2

# Optional: Private Operator Secret (set in Cloudflare + VeilX Popup -> Relay Auth Key)
npx.cmd wrangler secret put RELAY_SECRET
```

## Project structure

```
manifest.json            MV3 manifest (narrowed host permissions; composer is the only web-accessible page)
src/crypto.js            Keccak, ML-KEM-768, WebCrypto wrappers, VX1B binary encryption, relay PoW
src/protocol.js          Handshake, ratchet, wire format, key packets (pure functions)
src/session.js           Session state machine, chains, replay protection, media sidecars, local history
src/store.js             Storage, locking, Key Vault
src/content.js           Page script: scan, decrypt, key exchange, media sidecar fetch, fail-closed guards
src/dom.js, ui.js, styles.js, util.js   Instagram DOM helpers and closed shadow-DOM UI (<img>, <video>, <audio>)
src/background.js        Composer→page broker & Zero-Knowledge Relay proxy
composer/                Extension-origin composer iframe (text, original-byte media attach/drop, live voice notes)
popup/                   Obsidian Black Control Center & veilxweb.onrender.com launcher
server/                  Cloudflare Worker (worker.js, wrangler.toml) + Node loopback relay (local-relay.js)
tests/                   crypto, protocol, background, popup, content (DOM) tests + kat.json
docs/THREAT_MODEL.md
```

## Tests

```bash
npm test          # node --test tests/*.test.js
```

* **crypto & relay:** SHA-3/SHAKE vs OpenSSL; ML-KEM-768 known answers (`tests/kat.json`); FIPS 203 modulus and decapsulation-key checks; `VX1B` binary authenticated encryption; Cloudflare Worker `caches.default` 5-read burn cap enforcement even after cold isolate memory eviction; per-IP upload/byte/download rate limiting (`429 Too Many Requests`).
* **protocol:** handshake & matching safety codes, verification gating, forward-secrecy property, reorder / replay / reflection / tamper / forged-sequence cases, simultaneous offers, spliced key packets, chunking, passphrase mode, vault round trip.
* **background:** all network rules are tab-scoped; broker accepts only the composer and only targets the sender's tab.
* **popup / content:** real extension files in a simulated page — no keyboard events or window messages leak, only ciphertext reaches the send box, native-box typing is blocked, full exchange and messaging through the DOM, bit-for-bit original image (`<img>`), short video (`<video>`), and voice note (`<audio>`) sidecar delivery in 1 DM.

## Limitations

JavaScript cryptography is not constant-time and is not independently audited or FIPS-validated. Decrypted history is stored locally in plaintext (sealed by the Key Vault when locked). See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

Created by Rudra Pratap Shukla. Released under the [MIT License](LICENSE).
