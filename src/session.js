/**
 * src/session.js — conversation sessions: handshake state machine, sending and
 * receiving chains, replay protection, and the local decrypted-history store
 * (VeilX 1.0.0). Pure logic over VX.store + VX.protocol; no DOM access.
 *
 * Forward-secrecy model (what is and is not protected):
 *   • Handshake keys are ephemeral and deleted after use; the root key is never stored.
 *   • Each chain key is overwritten after every message; message keys are used once.
 *   • Therefore a device compromise does NOT reveal keys of messages already
 *     processed — only the *current* chain keys (future messages until the next
 *     rekey) and any skipped-message keys still waiting for out-of-order messages.
 *   • Readable history is kept as local plaintext (inh:/outh:), because a
 *     forward-secret messenger cannot re-decrypt old ciphertext. It is capped, is
 *     sealed by the Key Vault when locked, and is removed with "Forget this chat".
 *   • Passphrase mode has NO forward secrecy (the root key is persistent).
 */

globalThis.VX = globalThis.VX || {};

VX.session = (() => {
  "use strict";

  const P = VX.protocol;
  const C = VX.crypto;
  const { store, util } = VX;

  const MAX_HISTORY = 900;
  const MAX_HANDLED = 40;
  const MAX_SKIPPED = 300;
  const MAX_PP_SENDERS = 8;
  const MAX_PREV_SESSIONS = 5;

  const convLock = (t) => "conv:" + t;
  const sndKey = (c) => "snd:" + c;
  const rcvKey = (c) => "rcv:" + c;
  const inKey = (c) => "inh:" + c;
  const outKey = (c) => "outh:" + c;

  function pushHandled(rec, ...ids) {
    const set = new Set([...(rec.handled || []), ...ids]);
    return Array.from(set).slice(-MAX_HANDLED);
  }

  async function getStatus(threadId) {
    const rec = await store.getConversation(threadId);
    if (!rec) return { state: "none" };
    if (rec.convId && rec.mode === "passphrase") return { state: "passphrase", mode: "passphrase", verified: true };
    if (rec.convId) {
      return {
        state: "established", mode: "pq", verified: Boolean(rec.verified),
        safetyCode: rec.safetyCode || null, rekeying: Boolean(rec.offer),
      };
    }
    if (rec.offer) return { state: "offered", mode: "pq" };
    return { state: "none" };
  }

  // ── Session installation ─────────────────────────────────────────────────

  async function installSession(threadId, rec, derived, extra = {}) {
    const prev = (rec && rec.prev ? rec.prev.slice() : []);
    if (rec && rec.convId) {
      prev.push(rec.convId);
      while (prev.length > MAX_PREV_SESSIONS) prev.shift();
    }
    if (rec && rec.convId) {
      await store.removeState(sndKey(rec.convId));
      await store.removeState(rcvKey(rec.convId));
    }
    await store.setState(sndKey(derived.convIdB64), { sid: derived.sendSid, ckB64: derived.sendCkB64, n: 0 });
    await store.setState(rcvKey(derived.convIdB64), {
      chains: { [derived.peerSid]: { ckB64: derived.recvCkB64, n: 0, skipped: {} } },
    });
    const next = {
      mode: "pq",
      convId: derived.convIdB64,
      sendSid: derived.sendSid,
      peerSid: derived.peerSid,
      safetyCode: derived.safetyCode,
      verified: false,
      prev,
      handled: pushHandled(rec || {}, ...(extra.handled || [])),
    };
    await store.saveConversation(threadId, next);
    return next;
  }

  // ── Handshake ────────────────────────────────────────────────────────────

  /** Start (or restart) a key exchange. Returns the packets to post in the chat. */
  async function createOffer(threadId) {
    return store.withLock(convLock(threadId), async () => {
      await store.assertUnlocked();
      const rec = (await store.getConversation(threadId)) || {};
      if (rec.mode === "passphrase" && rec.convId) throw new Error("This chat uses a passphrase. Remove it first to switch to a key exchange.");
      const { offerB64, pending } = await P.createOffer();
      const hexId = P.toHex(C.sha3_256(C.base64ToBytes(offerB64)).subarray(0, 4));
      await store.saveConversation(threadId, {
        ...rec,
        offer: { offerB64, pending, createdAt: Date.now() },
        handled: pushHandled(rec, hexId),
      });
      return { packets: P.makeKeyPackets(offerB64) };
    });
  }

  /** Accept a contact's offer (user consent happens in the UI). Returns the reply packets to post. */
  async function acceptOffer(threadId, offerEntry) {
    return store.withLock(convLock(threadId), async () => {
      await store.assertUnlocked();
      const rec = (await store.getConversation(threadId)) || {};
      if (rec.mode === "passphrase" && rec.convId) throw new Error("This chat uses a passphrase.");
      const { replyB64, session } = await P.acceptOffer(offerEntry.payloadB64);
      const replyId = P.toHex(C.sha3_256(C.base64ToBytes(replyB64)).subarray(0, 4));
      const { offer: _dropOwnOffer, ...rest } = rec;
      await installSession(threadId, rest, session, { handled: [offerEntry.id, replyId] });
      return { packets: P.makeKeyPackets(replyB64) };
    });
  }

  async function processKeyEntries(threadId, entries) {
    const events = [];
    if (!entries.length) return events;
    const lastReply = [...entries].reverse().find((e) => e.kind === "reply");
    const lastOffer = [...entries].reverse().find((e) => e.kind === "offer");

    await store.withLock(convLock(threadId), async () => {
      let rec = await store.getConversation(threadId);

      if (lastReply && rec && rec.offer && !(rec.handled || []).includes(lastReply.id)) {
        try {
          const session = await P.finishOffer(rec.offer.pending, rec.offer.offerB64, lastReply.payloadB64);
          const { offer: _done, ...rest } = rec;
          rec = await installSession(threadId, rest, session, { handled: [lastReply.id] });
          events.push({ type: "established" });
        } catch (err) {
          if (globalThis.VX_DEBUG) console.error(err);
          await store.saveConversation(threadId, { ...rec, handled: pushHandled(rec, lastReply.id) });
          rec = await store.getConversation(threadId);
        }
      }

      if (lastOffer && !(rec && (rec.handled || []).includes(lastOffer.id)) && !(rec && rec.mode === "passphrase" && rec.convId)) {
        if (rec && rec.offer) {
          if (lastOffer.payloadB64 < rec.offer.offerB64) {
            const { replyB64, session } = await P.acceptOffer(lastOffer.payloadB64);
            const replyId = P.toHex(C.sha3_256(C.base64ToBytes(replyB64)).subarray(0, 4));
            const { offer: _abandoned, ...rest } = rec;
            await installSession(threadId, rest, session, { handled: [lastOffer.id, replyId] });
            events.push({ type: "auto-accepted", packets: P.makeKeyPackets(replyB64) });
          } else {
            await store.saveConversation(threadId, { ...rec, handled: pushHandled(rec, lastOffer.id) });
          }
        } else {
          events.push({ type: "offer-received", entry: lastOffer, replacesSession: Boolean(rec && rec.convId) });
        }
      }
    });
    return events;
  }

  async function declineOffer(threadId, entry) {
    return store.withLock(convLock(threadId), async () => {
      const rec = (await store.getConversation(threadId)) || {};
      await store.saveConversation(threadId, { ...rec, handled: pushHandled(rec, entry.id) });
    });
  }

  // ── Passphrase mode ──────────────────────────────────────────────────────

  async function setPassphrase(threadId, passphrase) {
    return store.withLock(convLock(threadId), async () => {
      await store.assertUnlocked();
      const rec = (await store.getConversation(threadId)) || {};
      const { rootB64, convIdB64 } = await P.sessionFromPassphrase(passphrase);
      if (rec.convId) {
        await store.removeState(sndKey(rec.convId));
        await store.removeState(rcvKey(rec.convId));
      }
      const sid = P.randomSid();
      await store.setState(sndKey(convIdB64), { sid, ckB64: await P.passphraseChain(rootB64, sid), n: 0 });
      await store.setState(rcvKey(convIdB64), { chains: {} });
      await store.saveConversation(threadId, {
        mode: "passphrase", convId: convIdB64, rootB64, sendSid: sid, verified: true,
        prev: rec.convId ? [...(rec.prev || []), rec.convId].slice(-MAX_PREV_SESSIONS) : rec.prev || [],
      });
    });
  }

  // ── History ──────────────────────────────────────────────────────────────

  async function loadHistory(key) {
    return (await store.getState(key)) || { order: [], items: {} };
  }

  async function addHistory(key, entryKey, value) {
    const h = await loadHistory(key);
    if (!(entryKey in h.items)) h.order.push(entryKey);
    h.items[entryKey] = value;
    while (h.order.length > MAX_HISTORY) delete h.items[h.order.shift()];
    await store.setState(key, h);
  }

  async function lookupHistory(rec, entryKey) {
    const ids = [rec.convId, ...(rec.prev || [])];
    for (const id of ids) {
      for (const k of [inKey(id), outKey(id)]) {
        const h = await store.getState(k);
        if (h && h.items && h.items[entryKey]) return h.items[entryKey];
      }
    }
    return null;
  }

  async function getGroupChunks(threadId, gid) {
    if (!threadId || !gid) return null;
    const rec = await store.getConversation(threadId);
    if (!rec || !rec.convId) return null;
    const ids = [rec.convId, ...(rec.prev || [])];
    const parts = {};
    let ct = 0;
    let m = null;
    for (const id of ids) {
      for (const k of [inKey(id), outKey(id)]) {
        const h = await store.getState(k);
        if (!h || !h.items) continue;
        for (const item of Object.values(h.items)) {
          if (item && item.gid === gid && typeof item.ci === "number") {
            parts[item.ci] = item.t;
            if (item.ct) ct = item.ct;
            if (item.m) m = item.m;
          }
        }
      }
    }
    return ct > 0 ? { ct, m, parts } : null;
  }

  // ── Sending ──────────────────────────────────────────────────────────────

  function fitChunks(text, pad, extraBase = {}) {
    let maxBytes = extraBase.m === "img" ? 600 : util.MAX_PLAINTEXT_BYTES;
    for (let attempt = 0; attempt < 8; attempt++) {
      const chunks = util.splitIntoChunks(text, maxBytes);
      const extra = chunks.length > 1
        ? { ...extraBase, gid: "xxxxxxxx", ci: 999, ct: 999 }
        : { ...extraBase };
      if (chunks.every((c) => P.estimateBlobChars(c, pad, extra) <= util.MAX_MESSAGE_CHARS - 20)) return chunks;
      maxBytes = Math.floor(maxBytes * 0.78);
      if (maxBytes < 16) break;
    }
    throw new Error("Message is too long to send as encrypted text.");
  }

  /**
   * Encrypts `text` for the chat. The advanced chain key is persisted BEFORE the
   * ciphertext is returned, so a message key can never be used twice.
   */
  async function encryptText(threadId, text, options = {}) {
    await store.assertUnlocked();
    const rec = await store.getConversation(threadId);
    if (!rec || !rec.convId) throw new Error("No key for this chat yet.");
    const settings = await store.getSettings();
    if (rec.mode === "pq" && settings.requireVerification && !rec.verified) {
      throw new Error("Verify the safety code before sending.");
    }
    const extraBase = {
      ...(options && options.m ? { m: options.m } : {}),
      ...(options && options.sidecar ? { sidecar: options.sidecar } : {}),
    };
    const usePad = options && typeof options.pad === "boolean" ? options.pad : settings.padMessages;
    const chunks = fitChunks(text, usePad, extraBase);
    const gid = chunks.length > 1 ? P.toHex(C.randomBytes(4)) : undefined;

    return store.withLock(sndKey(rec.convId), async () => {
      const blobs = [];
      for (let i = 0; i < chunks.length; i++) {
        const st = await store.getState(sndKey(rec.convId));
        if (!st) throw new Error("Sending chain missing; re-establish the key.");
        const { mk, next } = await P.ratchetStep(C.base64ToBytes(st.ckB64));
        const extra = chunks.length > 1
          ? { ...extraBase, gid, ci: i + 1, ct: chunks.length }
          : { ...extraBase };
        const blob = await P.sealMessage({
          mk, sid: st.sid, seq: st.n, convIdB64: rec.convId, text: chunks[i], pad: usePad, extra,
        });
        C.zeroize(mk);
        await store.setState(sndKey(rec.convId), { ...st, ckB64: C.bytesToBase64(next), n: st.n + 1 });
        await addHistory(outKey(rec.convId), `${st.sid}:${st.n}`, { t: chunks[i], ts: Date.now(), ...extra });
        blobs.push(blob);
      }
      return blobs;
    });
  }

  /**
   * Encrypts a Zero-Knowledge Sidecar Media Pointer (`{ u, k, h, mt, sz }`) into
   * a SINGLE forward-secret `VX1:` Instagram DM!
   */
  async function encryptMediaSidecar(threadId, sidecar) {
    if (!sidecar || typeof sidecar.u !== "string" || !sidecar.k || !sidecar.h) {
      throw new Error("Invalid sidecar media descriptor.");
    }
    return encryptText(threadId, "[VeilX Encrypted HD Media]", {
      m: "sidecar",
      pad: false,
      sidecar: {
        u: sidecar.u,
        k: sidecar.k,
        h: sidecar.h,
        mt: sidecar.mt || "image/webp",
        sz: Number(sidecar.sz || 0),
      },
    });
  }

  async function encryptImage(threadId, dataUrl) {
    if (
      typeof dataUrl !== "string" ||
      !/^data:image\/(webp|png|jpeg|jpg|gif);base64,[A-Za-z0-9+/=\s]+$/i.test(dataUrl.trim())
    ) {
      throw new Error("Unsupported or invalid image data URL.");
    }
    return encryptText(threadId, dataUrl.trim(), { m: "img", pad: false });
  }

  // ── Receiving ────────────────────────────────────────────────────────────

  async function decryptBlob(threadId, blobText) {
    const parsed = P.parseMessage(blobText);
    if (!parsed) return { ok: false, reason: "malformed" };
    const v = await store.getVaultStatus();
    if (v.locked) return { ok: false, reason: "locked" };
    const rec = await store.getConversation(threadId);
    if (!rec || !rec.convId) return { ok: false, reason: "no-key" };

    const entryKey = `${parsed.sid}:${parsed.seq}`;
    const done = (h) => ({
      ok: true,
      text: h.t,
      meta: {
        ts: h.ts,
        gid: h.gid,
        ci: h.ci,
        ct: h.ct,
        m: h.m,
        sidecar: h.sidecar || null,
        mode: rec.mode,
        verified: rec.mode === "passphrase" || Boolean(rec.verified),
      },
    });

    const cached = await lookupHistory(rec, entryKey);
    if (cached) return done(cached);

    const snd = await store.getState(sndKey(rec.convId));
    if (snd && snd.sid === parsed.sid) return { ok: false, reason: "own-unavailable" };

    return store.withLock(rcvKey(rec.convId), async () => {
      const again = await lookupHistory(rec, entryKey);
      if (again) return done(again);

      const st = (await store.getState(rcvKey(rec.convId))) || { chains: {} };
      let chain = st.chains[parsed.sid];
      if (!chain) {
        if (rec.mode !== "passphrase") return { ok: false, reason: "unknown-sender" };
        if (Object.keys(st.chains).length >= MAX_PP_SENDERS) return { ok: false, reason: "unknown-sender" };
        chain = { ckB64: await P.passphraseChain(rec.rootB64, parsed.sid), n: 0, skipped: {} };
      }

      let mk;
      let nextChain;
      if (parsed.seq < chain.n) {
        const sk = chain.skipped && chain.skipped[parsed.seq];
        if (!sk) return { ok: false, reason: "replay" };
        mk = C.base64ToBytes(sk);
        nextChain = { ...chain, skipped: { ...chain.skipped } };
        delete nextChain.skipped[parsed.seq];
      } else {
        if (parsed.seq - chain.n > P.MAX_SKIP) return { ok: false, reason: "too-far" };
        let ck = C.base64ToBytes(chain.ckB64);
        const skipped = { ...(chain.skipped || {}) };
        for (let i = chain.n; i < parsed.seq; i++) {
          const step = await P.ratchetStep(ck);
          skipped[i] = C.bytesToBase64(step.mk);
          ck = step.next;
        }
        const step = await P.ratchetStep(ck);
        mk = step.mk;
        const keys = Object.keys(skipped).map(Number).sort((a, b) => a - b);
        while (keys.length > MAX_SKIPPED) delete skipped[keys.shift()];
        nextChain = { ckB64: C.bytesToBase64(step.next), n: parsed.seq + 1, skipped };
      }

      let env;
      try {
        env = await P.openMessage({ mk, parsed, convIdB64: rec.convId });
      } catch (_) {
        return { ok: false, reason: "bad" };
      } finally {
        C.zeroize(mk);
      }

      await store.setState(rcvKey(rec.convId), { chains: { ...st.chains, [parsed.sid]: nextChain } });
      const meta = {
        t: env.t,
        ts: env.ts,
        gid: env.gid,
        ci: env.ci,
        ct: env.ct,
        ...(env.m ? { m: env.m } : {}),
        ...(env.sidecar ? { sidecar: env.sidecar } : {}),
      };
      await addHistory(inKey(rec.convId), entryKey, meta);
      return done(meta);
    });
  }

  return {
    getStatus, createOffer, acceptOffer, declineOffer, processKeyEntries,
    setPassphrase, encryptText, encryptMediaSidecar, encryptImage, decryptBlob, getGroupChunks,
  };
})();

if (typeof module !== "undefined") module.exports = VX.session;
