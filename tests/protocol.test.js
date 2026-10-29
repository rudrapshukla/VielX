/**
 * tests/protocol.test.js — handshake, forward secrecy, replay/reorder/reflection,
 * tamper resistance, key-packet integrity, passphrase mode.
 */
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { makeParty } = require("./helpers.js");

const T = "thread";

async function establish(A, B, { verify = true } = {}) {
  const offer = await A.session.createOffer(T);
  const [entry] = B.protocol.reassembleKeyPackets(offer.packets);
  const [ev] = await B.session.processKeyEntries(T, [entry]);
  assert.equal(ev.type, "offer-received");
  const reply = await B.session.acceptOffer(T, ev.entry);
  const entries = A.protocol.reassembleKeyPackets([...offer.packets, ...reply.packets]);
  const [evA] = await A.session.processKeyEntries(T, entries);
  assert.equal(evA.type, "established");
  if (verify) { await A.store.verifyConversation(T); await B.store.verifyConversation(T); }
  return { offer, reply };
}

test("handshake: both sides derive the same 128-bit safety code; sending is blocked until verified", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B, { verify: false });
  const a = await A.session.getStatus(T), b = await B.session.getStatus(T);
  assert.equal(a.safetyCode, b.safetyCode);
  assert.match(a.safetyCode, /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
  await assert.rejects(A.session.encryptText(T, "hi"), /Verify/);
  await assert.rejects(B.session.encryptText(T, "hi"), /Verify/);
  await A.store.verifyConversation(T);
  assert.equal((await A.session.encryptText(T, "hi")).length, 1);
});

test("every handshake uses fresh keys: two exchanges give different codes", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const first = (await A.session.getStatus(T)).safetyCode;
  await establish(A, B);
  assert.notEqual((await A.session.getStatus(T)).safetyCode, first);
});

test("forward secrecy: no stored secret can recover keys of messages already processed", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const m1 = (await A.session.encryptText(T, "secret one"))[0];
  const m2 = (await A.session.encryptText(T, "secret two"))[0];
  assert.equal((await B.session.decryptBlob(T, m1)).text, "secret one");
  assert.equal((await B.session.decryptBlob(T, m2)).text, "secret two");

  // Attacker steals EVERYTHING in B's storage after both messages were read, and wipes B's plaintext history.
  const stolen = JSON.parse(JSON.stringify(B.data));
  const rec = stolen[`conv:${T}`];
  for (const k of Object.keys(stolen)) if (k.startsWith("inh:") || k.startsWith("outh:")) delete stolen[k];

  // 1) No ephemeral handshake key and no root key remain anywhere.
  const dump = JSON.stringify(stolen);
  for (const needle of ["ecPrivJwk", "dkB64", "rootB64", '"pending"']) assert.ok(!dump.includes(needle), needle);
  // 2) The stolen chain key is ahead of m1/m2: it cannot open them.
  const chain = Object.values(stolen[`rcv:${rec.convId}`].chains)[0];
  const parsed1 = B.protocol.parseMessage(m1);
  let ck = B.crypto.base64ToBytes(chain.ckB64);
  const { mk } = await B.protocol.ratchetStep(ck);
  await assert.rejects(B.protocol.openMessage({ mk, parsed: parsed1, convIdB64: rec.convId }));
  assert.ok(chain.n >= 2 && Object.keys(chain.skipped).length === 0);
});

test("out-of-order delivery works; duplicate rendering uses history; replay after history loss is rejected", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const blobs = [];
  for (const t of ["one", "two", "three"]) blobs.push((await A.session.encryptText(T, t))[0]);
  assert.equal((await B.session.decryptBlob(T, blobs[2])).text, "three");
  assert.equal((await B.session.decryptBlob(T, blobs[0])).text, "one");
  assert.equal((await B.session.decryptBlob(T, blobs[1])).text, "two");
  assert.equal((await B.session.decryptBlob(T, blobs[1])).text, "two"); // re-render: from history
  const rec = await B.store.getConversation(T);
  delete B.data["inh:" + rec.convId];
  assert.equal((await B.session.decryptBlob(T, blobs[1])).reason, "replay");
});

test("reflection: a message cannot be bounced back as if the contact sent it", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const m = (await A.session.encryptText(T, "mine"))[0];
  const rec = await A.store.getConversation(T);
  delete A.data["outh:" + rec.convId];
  assert.equal((await A.session.decryptBlob(T, m)).reason, "own-unavailable");
});

test("tampering with header, body, or tag fails without changing any state", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const m = (await A.session.encryptText(T, "payload"))[0];
  const before = JSON.stringify(B.data);
  const flip = (blob, idx) => {
    const raw = Buffer.from(blob.slice(4), "base64"); raw[idx] ^= 1; return "VX1:" + raw.toString("base64");
  };
  for (const idx of [0, 2, 9, 12, 14, 30, Buffer.from(m.slice(4), "base64").length - 1]) {
    const r = await B.session.decryptBlob(T, flip(m, idx));
    assert.equal(r.ok, false, "idx " + idx);
  }
  assert.equal(JSON.stringify(B.data), before, "state unchanged by forged messages");
  assert.equal((await B.session.decryptBlob(T, m)).text, "payload");
});

test("a forged far-future sequence number is rejected cheaply and without state change", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const m = (await A.session.encryptText(T, "x"))[0];
  const raw = Buffer.from(m.slice(4), "base64");
  raw.writeUInt32BE(5000, 9);
  const before = JSON.stringify(B.data);
  assert.equal((await B.session.decryptBlob(T, "VX1:" + raw.toString("base64"))).reason, "too-far");
  assert.equal(JSON.stringify(B.data), before);
});

test("a message from one conversation never decrypts in another (convId is authenticated)", async () => {
  const A = makeParty(), B = makeParty(), C = makeParty();
  await establish(A, B);
  const A2 = makeParty(), C2 = makeParty();
  await establish(A2, C2);
  const m = (await A.session.encryptText(T, "for B only"))[0];
  assert.equal((await C2.session.decryptBlob(T, m)).ok, false);
  assert.equal((await B.session.decryptBlob("some-other-thread", m)).reason, "no-key");
});

test("simultaneous offers converge on ONE session (smaller offer wins, the other yields)", async () => {
  const A = makeParty(), B = makeParty();
  const oa = await A.session.createOffer(T);
  const ob = await B.session.createOffer(T);
  const ea = B.protocol.reassembleKeyPackets(oa.packets);
  const eb = A.protocol.reassembleKeyPackets(ob.packets);
  const evA = await A.session.processKeyEntries(T, eb);
  const evB = await B.session.processKeyEntries(T, ea);
  const yielder = evA.find((e) => e.type === "auto-accepted") ? "A" : "B";
  const winner = yielder === "A" ? B : A;
  const loser = yielder === "A" ? A : B;
  const yEvents = yielder === "A" ? evA : evB;
  const reply = yEvents.find((e) => e.type === "auto-accepted").packets;
  const winOffer = yielder === "A" ? ob.packets : oa.packets;
  const [wEv] = await winner.session.processKeyEntries(T, winner.protocol.reassembleKeyPackets([...winOffer, ...reply]));
  assert.equal(wEv.type, "established");
  assert.equal((await winner.session.getStatus(T)).safetyCode, (await loser.session.getStatus(T)).safetyCode);
});

test("key packets: spliced or corrupted bundles are dropped; the bundle id commits to the payload", async () => {
  const A = makeParty(), E = makeParty();
  const real = await A.session.createOffer(T);
  const evil = await E.session.createOffer(T);
  const id = real.packets[0].match(/#([0-9a-f]{8})#/)[1];
  const spliced = [real.packets[0], evil.packets[1].replace(/#[0-9a-f]{8}#/, `#${id}#`)];
  assert.equal(A.protocol.reassembleKeyPackets(spliced).length, 0);
  assert.equal(A.protocol.reassembleKeyPackets(real.packets).length, 1);
  assert.equal(A.protocol.parseKeyPacket(real.packets[0] + "garbage!"), null);
});

test("a reply that does not belong to our offer is ignored", async () => {
  const A = makeParty(), B = makeParty(), M = makeParty();
  const offerA = await A.session.createOffer(T);
  const offerM = await M.session.createOffer("x");
  const [eM] = B.protocol.reassembleKeyPackets(offerM.packets);
  const replyToM = await B.session.acceptOffer(T, eM);
  const evs = await A.session.processKeyEntries(T, A.protocol.reassembleKeyPackets([...offerA.packets, ...replyToM.packets]));
  assert.equal(evs.length, 0);
  assert.equal((await A.session.getStatus(T)).state, "offered");
});

test("a new offer from the contact never replaces an established session silently", async () => {
  const A = makeParty(), B = makeParty(), N = makeParty();
  await establish(A, B);
  const code = (await A.session.getStatus(T)).safetyCode;
  const o = await N.session.createOffer(T);
  const evs = await A.session.processKeyEntries(T, A.protocol.reassembleKeyPackets(o.packets));
  assert.equal(evs[0].type, "offer-received");
  assert.equal(evs[0].replacesSession, true);
  assert.equal((await A.session.getStatus(T)).safetyCode, code);
});

test("chunking: long / escape-heavy messages split so every ciphertext fits Instagram's limit", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const long = "é".repeat(900) + " " + '"'.repeat(300) + " " + "日本語".repeat(120);
  const blobs = await A.session.encryptText(T, long);
  assert.ok(blobs.length > 1);
  let joined = "";
  for (const b of blobs) {
    assert.ok(b.length < 1000, `blob ${b.length}`);
    const r = await B.session.decryptBlob(T, b);
    assert.ok(r.ok);
    joined += r.text;
  }
  assert.equal(joined.replace(/\s/g, ""), long.replace(/\s/g, ""));
});

test("passphrase mode: two senders interoperate, replay is blocked, and it is clearly marked no-FS", async () => {
  const A = makeParty(), B = makeParty();
  const pass = A.crypto.generatePassphrase();
  await A.session.setPassphrase(T, pass);
  await B.session.setPassphrase(T, pass);
  assert.equal((await A.session.getStatus(T)).state, "passphrase");
  const a1 = (await A.session.encryptText(T, "from A"))[0];
  const b1 = (await B.session.encryptText(T, "from B"))[0];
  assert.equal((await B.session.decryptBlob(T, a1)).text, "from A");
  assert.equal((await A.session.decryptBlob(T, b1)).text, "from B");
  const rec = await B.store.getConversation(T);
  delete B.data["inh:" + rec.convId];
  assert.equal((await B.session.decryptBlob(T, a1)).reason, "replay");
  await assert.rejects(A.session.setPassphrase(T, "not generated by veilx"), /generated by VeilX/);
});

test("a locked vault blocks creating or changing key material", async () => {
  const A = makeParty();
  await A.store.setSetting("vaultLocked", true);
  await A.store.setSetting("vaultEnvelope", { v: 1 });
  await assert.rejects(A.session.createOffer(T), /locked/);
  await assert.rejects(A.session.setPassphrase(T, A.crypto.generatePassphrase()), /locked/);
});

test("vault round trip keeps sessions working (lock removes plaintext keys, unlock restores them)", async () => {
  const A = makeParty(), B = makeParty();
  await establish(A, B);
  const m = (await A.session.encryptText(T, "before lock"))[0];
  await B.store.lockVault("a long master passphrase");
  assert.ok(!Object.keys(B.data).some((k) => /^(conv|snd|rcv|inh|outh):/.test(k)), "no plaintext secrets left");
  assert.equal((await B.session.decryptBlob(T, m)).reason, "locked");
  await B.store.unlockVault("a long master passphrase");
  assert.equal((await B.session.decryptBlob(T, m)).text, "before lock");
});
