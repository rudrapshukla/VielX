/**
 * src/protocol.js — VeilX 1.0.0 protocol (pure functions, no storage, no DOM).
 *
 * Handshake ("hybrid KEM + DH", two messages, fresh keys every time):
 *   Initiator → Responder   OFFER = ecPubI(65) ‖ mlkemEk(1184)                    (1249 B)
 *   Responder → Initiator   REPLY = ecPubR(65) ‖ mlkemCt(1088) ‖ H(OFFER)[0:16]   (1169 B)
 *
 *   TH   = SHA-256("veilx-v1-transcript" ‖ OFFER ‖ ecPubR ‖ mlkemCt)
 *   root = HKDF-SHA256(ikm = ECDH(ephI, ephR) ‖ mlkemSharedSecret, salt = TH, info = "veilx-v1-root")
 *
 * All handshake private keys are ephemeral, are used once, and are deleted
 * after the root key is derived; the root key itself is also discarded once
 * the two directional chain keys are derived. Compromising a device later
 * therefore reveals neither past chain keys nor the handshake secrets.
 *
 * Messages use a per-direction symmetric hash ratchet:
 *   mk_i = HMAC(ck_i, 0x01),  ck_{i+1} = HMAC(ck_i, 0x02)    (ck_i is then deleted)
 * Wire format: "VX1:" ‖ base64( 0x01 ‖ sid(8) ‖ seq(4, BE) ‖ iv(12) ‖ AES-256-GCM(...) )
 * AAD = "veilx-v1-msg" ‖ header ‖ convId, so header, direction (sid), sequence
 * number and conversation are all authenticated.
 */

globalThis.VX = globalThis.VX || {};

VX.protocol = (() => {
  "use strict";

  const C = VX.crypto;
  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: true });

  const MSG_PREFIX = "VX1:";
  const KEY_PREFIX = "VX1K:";
  const OFFER_BYTES = C.P256_PUB_BYTES + C.MLKEM_EK_BYTES; // 1249
  const REPLY_BYTES = C.P256_PUB_BYTES + C.MLKEM_CT_BYTES + 16; // 1169
  const KEY_CHUNK_CHARS = 900;
  const MAX_KEY_PACKETS = 4;
  const MAX_SKIP = 300;
  const HEADER_BYTES = 13;
  const MSG_AAD_LABEL = enc.encode("veilx-v1-msg");
  const EMPTY = new Uint8Array(0);

  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const fromHex = (hex) => {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  };

  // ── Handshake ────────────────────────────────────────────────────────────

  async function transcriptHash(offer, ecPubR, ct) {
    return C.sha256(C.concatBytes(enc.encode("veilx-v1-transcript"), offer, ecPubR, ct));
  }

  async function deriveFromRoot(root, th, role) {
    const [convId, sidI, sidR, ckI, ckR, codeSeed] = await Promise.all([
      C.hkdf(root, EMPTY, "veilx-v1-conv-id", 16),
      C.hkdf(root, EMPTY, "veilx-v1-sid-init", 8),
      C.hkdf(root, EMPTY, "veilx-v1-sid-resp", 8),
      C.hkdf(root, EMPTY, "veilx-v1-chain-init", 32),
      C.hkdf(root, EMPTY, "veilx-v1-chain-resp", 32),
      C.sha256(C.concatBytes(enc.encode("veilx-v1-safety"), th)),
    ]);
    const init = role === "init";
    return {
      convIdB64: C.bytesToBase64(convId),
      sendSid: toHex(init ? sidI : sidR),
      peerSid: toHex(init ? sidR : sidI),
      sendCkB64: C.bytesToBase64(init ? ckI : ckR),
      recvCkB64: C.bytesToBase64(init ? ckR : ckI),
      safetyCode: formatSafetyCode(codeSeed.subarray(0, 16)),
    };
  }

  /** 128-bit safety code: 8 groups of 4 hex characters. */
  function formatSafetyCode(bytes16) {
    return toHex(bytes16).match(/.{4}/g).join(" ").toUpperCase();
  }

  /** Initiator, step 1. Generates ephemeral keys; the private part must be stored until the reply arrives. */
  async function createOffer() {
    const ec = await C.generateEcdhKeyPair();
    const kem = C.mlkem768KeyGen();
    return {
      offerB64: C.bytesToBase64(C.concatBytes(ec.pubRaw, kem.ek)),
      pending: { ecPrivJwk: ec.privJwk, dkB64: C.bytesToBase64(kem.dk) },
    };
  }

  /** Responder: consumes an OFFER, returns the REPLY and the derived session. All ephemeral secrets are discarded. */
  async function acceptOffer(offerB64) {
    const offer = C.base64ToBytes(offerB64);
    if (offer.length !== OFFER_BYTES) throw new Error("Malformed key offer");
    const ecPubI = offer.subarray(0, C.P256_PUB_BYTES);
    const ek = offer.subarray(C.P256_PUB_BYTES);

    const ec = await C.generateEcdhKeyPair();
    const dh = await C.ecdhDerive(ec.privJwk, ecPubI);
    const { ct, ss } = C.mlkem768Encaps(ek);
    const th = await transcriptHash(offer, ec.pubRaw, ct);
    const root = await C.hkdf(C.concatBytes(dh, ss), th, "veilx-v1-root", 32);
    const session = await deriveFromRoot(root, th, "resp");
    const tag = (await C.sha256(offer)).subarray(0, 16);
    C.zeroize(root); C.zeroize(dh); C.zeroize(ss);
    ec.privJwk = null;
    return { replyB64: C.bytesToBase64(C.concatBytes(ec.pubRaw, ct, tag)), session };
  }

  /** Initiator, step 2: consumes the REPLY. Returns the session, or throws if the reply does not belong to this offer. */
  async function finishOffer(pending, offerB64, replyB64) {
    const offer = C.base64ToBytes(offerB64);
    const reply = C.base64ToBytes(replyB64);
    if (reply.length !== REPLY_BYTES) throw new Error("Malformed key reply");
    const ecPubR = reply.subarray(0, C.P256_PUB_BYTES);
    const ct = reply.subarray(C.P256_PUB_BYTES, C.P256_PUB_BYTES + C.MLKEM_CT_BYTES);
    const tag = reply.subarray(C.P256_PUB_BYTES + C.MLKEM_CT_BYTES);
    const expected = (await C.sha256(offer)).subarray(0, 16);
    if (!C.timingSafeEqualBytes(tag, expected)) throw new Error("Reply is not for this offer");

    const dh = await C.ecdhDerive(pending.ecPrivJwk, ecPubR);
    const ss = C.mlkem768Decaps(C.base64ToBytes(pending.dkB64), ct);
    const th = await transcriptHash(offer, ecPubR, ct);
    const root = await C.hkdf(C.concatBytes(dh, ss), th, "veilx-v1-root", 32);
    const session = await deriveFromRoot(root, th, "init");
    C.zeroize(root); C.zeroize(dh); C.zeroize(ss);
    return session;
  }

  // ── Passphrase mode (no forward secrecy: the root persists) ─────────────

  async function sessionFromPassphrase(passphrase) {
    const root = await C.deriveRootFromPassphrase(passphrase);
    const convId = await C.hkdf(root, EMPTY, "veilx-v1-pp-conv-id", 16);
    const out = { rootB64: C.bytesToBase64(root), convIdB64: C.bytesToBase64(convId) };
    C.zeroize(root);
    return out;
  }

  /** Per-sender chain in passphrase mode: any sid is accepted and gets its own chain. */
  async function passphraseChain(rootB64, sidHex) {
    const ck = await C.hkdf(C.base64ToBytes(rootB64), EMPTY, C.concatBytes(enc.encode("veilx-v1-pp-chain"), fromHex(sidHex)), 32);
    return C.bytesToBase64(ck);
  }

  function randomSid() {
    return toHex(C.randomBytes(8));
  }

  // ── Ratchet & messages ───────────────────────────────────────────────────

  async function ratchetStep(ckBytes) {
    const [mk, next] = await Promise.all([
      C.hmacSha256(ckBytes, Uint8Array.of(0x01)),
      C.hmacSha256(ckBytes, Uint8Array.of(0x02)),
    ]);
    return { mk, next };
  }

  function buildHeader(sidHex, seq) {
    const h = new Uint8Array(HEADER_BYTES);
    h[0] = 0x01;
    h.set(fromHex(sidHex), 1);
    new DataView(h.buffer).setUint32(9, seq >>> 0, false);
    return h;
  }

  function messageAad(header, convIdBytes) {
    return C.concatBytes(MSG_AAD_LABEL, header, convIdBytes);
  }

  /** Returns "VX1:<base64>" for one message. `envelope` extras: gid, ci, ct, m. */
  async function sealMessage({ mk, sid, seq, convIdB64, text, pad = true, extra = {} }) {
    const header = buildHeader(sid, seq);
    const body = enc.encode(JSON.stringify({ t: text, ts: Date.now(), ...extra }));
    const plain = C.concatBytes(Uint8Array.of(pad ? 0x02 : 0x01), pad ? C.padBytes(body, 32) : body);
    const sealed = await C.aesGcmSeal(mk, plain, messageAad(header, C.base64ToBytes(convIdB64)));
    return MSG_PREFIX + C.bytesToBase64(C.concatBytes(header, sealed));
  }

  /** Cheap structural parse (no crypto). Returns null if the blob is not a well-formed VX1 message. */
  function parseMessage(text) {
    if (typeof text !== "string") return null;
    const cleaned = text.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, "");
    const m = /^VX1:([A-Za-z0-9+/]+={0,2})$/.exec(cleaned);
    if (!m) return null;
    let bytes;
    try { bytes = C.base64ToBytes(m[1]); } catch (_) { return null; }
    if (bytes.length < HEADER_BYTES + C.IV_BYTES + C.TAG_BYTES + 1 || bytes[0] !== 0x01) return null;
    const header = bytes.subarray(0, HEADER_BYTES);
    return {
      blob: MSG_PREFIX + m[1],
      header,
      sid: toHex(header.subarray(1, 9)),
      seq: new DataView(header.buffer, header.byteOffset, HEADER_BYTES).getUint32(9, false),
      sealed: bytes.subarray(HEADER_BYTES),
    };
  }

  /** Authenticated decrypt. Throws on any failure (wrong key, tampered header, wrong conversation). */
  async function openMessage({ mk, parsed, convIdB64 }) {
    const plain = await C.aesGcmOpen(mk, parsed.sealed, messageAad(parsed.header, C.base64ToBytes(convIdB64)));
    const mode = plain[0];
    let body = plain.subarray(1);
    if (mode === 0x02) body = C.unpadBytes(body);
    else if (mode !== 0x01) body = null;
    if (!body) throw new Error("Malformed message body");
    const env = JSON.parse(dec.decode(body));
    if (!env || typeof env.t !== "string") throw new Error("Malformed message envelope");
    return env;
  }

  /** Exact length of the "VX1:..." blob that sealMessage would produce (used to chunk before ratcheting). */
  function estimateBlobChars(text, pad = true, extra = {}) {
    const jsonLen = enc.encode(JSON.stringify({ t: text, ts: 1700000000000, ...extra })).length;
    const rem = (jsonLen + 1) % 32;
    const padded = pad ? jsonLen + (rem === 0 ? 1 : 32 - rem + 1) : jsonLen;
    const raw = HEADER_BYTES + C.IV_BYTES + 1 + padded + C.TAG_BYTES;
    return MSG_PREFIX.length + 4 * Math.ceil(raw / 3);
  }

  // ── Key packets ──────────────────────────────────────────────────────────

  function makeKeyPackets(payloadB64) {
    const id = toHex(C.sha3_256(C.base64ToBytes(payloadB64)).subarray(0, 4));
    const chunks = [];
    for (let i = 0; i < payloadB64.length; i += KEY_CHUNK_CHARS) chunks.push(payloadB64.slice(i, i + KEY_CHUNK_CHARS));
    return chunks.map((c, i) => `${KEY_PREFIX}P${i + 1}/${chunks.length}#${id}#${c}`);
  }

  function parseKeyPacket(text) {
    if (typeof text !== "string") return null;
    const cleaned = text.replace(/[\s\u200b-\u200d\u2060\ufeff]/g, "");
    const m = /^VX1K:P(\d{1,2})\/(\d{1,2})#([0-9a-f]{8})#([A-Za-z0-9+/]+={0,2})$/.exec(cleaned);
    if (!m) return null;
    const index = Number(m[1]);
    const total = Number(m[2]);
    if (total < 1 || total > MAX_KEY_PACKETS || index < 1 || index > total) return null;
    return { index, total, id: m[3], chunk: m[4] };
  }

  /**
   * Reassembles packets (in DOM order) into complete, hash-verified key messages.
   * Returns [{ kind: "offer" | "reply", payloadB64, id }] in order of completion.
   */
  function reassembleKeyPackets(texts) {
    const groups = new Map();
    const out = [];
    for (const t of texts) {
      const p = parseKeyPacket(t);
      if (!p) continue;
      const gk = `${p.id}/${p.total}`;
      let g = groups.get(gk);
      if (!g) { g = new Map(); groups.set(gk, g); }
      g.set(p.index, p.chunk);
      if (g.size !== p.total) continue;
      let payload = "";
      let complete = true;
      for (let i = 1; i <= p.total; i++) {
        if (!g.has(i)) { complete = false; break; }
        payload += g.get(i);
      }
      if (!complete) continue;
      groups.delete(gk);
      let bytes;
      try { bytes = C.base64ToBytes(payload); } catch (_) { continue; }
      // The id commits to the payload; a spliced or corrupted bundle is dropped.
      if (toHex(C.sha3_256(bytes).subarray(0, 4)) !== p.id) continue;
      if (bytes.length === OFFER_BYTES) out.push({ kind: "offer", payloadB64: payload, id: p.id });
      else if (bytes.length === REPLY_BYTES) out.push({ kind: "reply", payloadB64: payload, id: p.id });
    }
    return out;
  }

  return {
    MSG_PREFIX, KEY_PREFIX, OFFER_BYTES, REPLY_BYTES, MAX_SKIP, HEADER_BYTES,
    toHex, fromHex,
    createOffer, acceptOffer, finishOffer,
    sessionFromPassphrase, passphraseChain, randomSid,
    ratchetStep, estimateBlobChars, sealMessage, parseMessage, openMessage,
    makeKeyPackets, parseKeyPacket, reassembleKeyPackets,
  };
})();

if (typeof module !== "undefined") module.exports = VX.protocol;
