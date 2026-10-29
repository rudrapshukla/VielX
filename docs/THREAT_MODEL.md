# VeilX 1.1.0 — Threat Model

This document states what VeilX protects, against whom, and — just as important — what it does not.

## Assumed adversaries

| Adversary | Capability |
|---|---|
| **Passive network / server recorder** (Meta, ISP, Cloudflare relay operator, state) | Stores every Instagram DM ciphertext (`VX1:`), key packet (`VX1K:`), and encrypted media blob (`VX1B`) forever; may have a future quantum computer ("harvest now, decrypt later"). |
| **Active server / transport / relay attacker** | Can drop, reorder, replay, inject and *modify* chat messages or substitute encrypted `VX1B` blobs on the relay. |
| **Passive page script** | Instagram's own JavaScript, unaware of VeilX, running in the same page. |
| **Device thief / later malware** | Reads the browser profile *after* some messages were exchanged. |

## Guarantees

| Property | Status | How |
|---|---|---|
| Confidentiality against a passive recorder, now and against future quantum computers | **Yes** | Root key = HKDF(ECDH-P256 ‖ ML-KEM-768 shared secret); an attacker must break **both**. Media sidecars (`VX1B`) use a fresh random 256-bit AES-256-GCM key per attachment, transmitted inside the forward-secret `VX1:` chat ratchet. |
| Original-byte media fidelity (Sidecar Relay path) | **Yes** | On the Sidecar Relay path, `composer.js` reads `file.arrayBuffer()` directly and encrypts the **exact original file bytes** without `<canvas>` resizing or lossy re-encoding (up to 15 MB per image, short video, or voice note). |
| Integrity against a malicious or compromised relay | **Yes** | The forward-secret `VX1:` pointer message commits to `SHA-256(VX1B_envelope)`, the one-time 256-bit key `k`, and the MIME type bound as AES-GCM AAD (`veilx-v1-media:<mime>`). If the relay modifies a single byte of the blob, verification fails before rendering. |
| Forward secrecy against later device compromise | **Yes** (key-exchange mode) | Handshake keys are ephemeral and deleted; the root key is never stored; chain keys are overwritten per message and each message key is used once. Only the *current* chain keys (future messages until rekey) and any keys held for out-of-order messages are exposed. |
| Key freshness | **Yes** | Every exchange generates new ephemeral keys; there is no long-term identity key to steal. |
| Replay / reflection / reordering of ciphertext | **Detected** | Per-direction chains; authenticated header (direction `sid`, sequence number, conversation id); persistent receive state. |
| Cross-conversation splicing | **Blocked** | Conversation id is authenticated as AES-GCM AAD. |
| Message tampering | **Detected** | AES-256-GCM; failures change no state. |
| Active key substitution (MITM by whoever controls the chat) | **Only if the safety code is compared** | Unauthenticated exchange by design (no account PKI). The 128-bit safety code covers the full transcript (both ephemeral public keys, the KEM ciphertext). Sending is **blocked until verified** by default. |

## Public Prototype Relay & Abuse Controls

1. **No client secret is claimed in public mode.** A value shipped inside a downloadable browser extension cannot act as a secret client credential. In default public mode, `PUBLIC_RELAY_BINDING_TAG` (`veilx-public-prototype-v1`) serves strictly as a request-integrity binding over `(timestamp, sha256, powNonce)` paired with a 14-bit SHA3-256 Hashcash Proof-of-Work (`X-VeilX-PoW`).
2. **Server-side abuse controls enforce real quotas.** Both `server/worker.js` and `server/local-relay.js` enforce per-IP sliding-window quotas (`15 uploads / 10 min`, `50 MB / 10 min`, `60 downloads / 10 min`, returning `429 Too Many Requests`), a strict `15 MB` per-blob limit, `VX1B\x01` header validation, SHA-256 body verification, and a 5-download / 24-hour burn cap across R2 (`env.VEILX_BUCKET`), Cloudflare Edge Cache (`caches.default`), and isolate memory.
3. **Private operator mode.** Teams self-hosting a private relay can configure a non-empty secret (`wrangler secret put RELAY_SECRET`) and enter the matching key in the VeilX popup settings.
4. **R2 vs. Edge Cache durability.** When deployed without `[env.r2]`, the Worker uses Cloudflare's regional `caches.default` and isolate memory (`edgeMemoryStore`), both of which enforce the 5-read burn counter. However, Edge Cache entries can be evicted before 24 hours under regional cache pressure; production deployments requiring guaranteed 24-hour retention across all global PoPs should deploy with `--env r2`.

## Least-Privilege Extension Permissions

`manifest.json` requests only the minimum required permissions:
* `storage`: stores session ratchets, verified status, and optional Key Vault ciphertext in `chrome.storage.local`.
* `declarativeNetRequest`: installs tab-scoped framing rules only when a VeilX Studio tab is open.
* `host_permissions`: narrowed strictly to `https://www.instagram.com/*`, `https://*.instagram.com/*`, `https://*.facebook.com/*`, `https://veilx-relay.therealrudrashukla.workers.dev/*`, and localhost loopback (`http://127.0.0.1/*`, `http://localhost/*`).

## Explicit non-guarantees

1. **An active attacker defeats an unverified chat.** Post-quantum cryptography does not authenticate anyone. Compare the safety code over a channel Instagram does not control.
2. **A hostile page can defeat the composer isolation.** The composer lives in a separate extension-origin iframe, so Instagram's JavaScript cannot read keystrokes *passively*. VeilX fails *closed* — typing in Instagram's own box is blocked, never encrypted or sent — but it cannot stop a user from typing into a spoofed field outside the iframe.
3. **Readable history is local plaintext.** A forward-secret messenger cannot decrypt old ciphertext again, so decrypted messages are kept (capped at 300 per direction per chat) in `chrome.storage.local`. The Key Vault seals it while locked; full-disk encryption is still recommended; "Remove key" deletes it.
4. **The Key Vault is best-effort.** It seals keys and history under a passphrase while locked and overwrites then deletes the plaintext entries, but the browser's on-disk database may retain old pages until compaction.
5. **Passphrase mode has no forward secrecy** (the root persists) and only accepts VeilX-generated 100-bit passphrases.
6. **Offline in-band image fallback is lossy.** While the default Sidecar Relay path encrypts original file bytes bit-for-bit without re-encoding, the offline in-band fallback resizes images to fit within Instagram's message chunk limits.
7. **Metadata is not hidden.** Meta sees who talks to whom, when, message counts and sizes (padded to 32-byte blocks), and that VeilX is in use.
8. **The cryptography is implemented in JavaScript.** It is verified against an independent audited implementation (see `tests/kat.json`), but JavaScript engines give no constant-time guarantee, and the code has not been through FIPS 140 / CAVP validation or an independent audit.
9. **One chain per direction means a compromised *current* chain key decrypts that direction until the next key exchange.** Start a new exchange periodically ("Start a new key exchange" in the popup).
