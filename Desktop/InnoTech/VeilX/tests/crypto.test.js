/**
 * tests/crypto.test.js — automatic checks for src/crypto.js (VeilX v5.0)
 *
 * HOW TO RUN:
 *     node --test tests/crypto.test.js
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../src/crypto.js");

const zeroKeyBytes = new Uint8Array(32);

test("encrypt then decrypt returns the original text", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const blob = await C.encryptMessage(key, "namaste 🙏 नमस्ते");
  assert.ok(blob.startsWith("GPV2:"));
  assert.equal(await C.decryptMessage(key, blob), "namaste 🙏 नमस्ते");
});

test("same text encrypts to different output every time (fresh IV)", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const a = await C.encryptMessage(key, "hello");
  const b = await C.encryptMessage(key, "hello");
  assert.notEqual(a, b);
});

test("a wrong key fails to decrypt", async () => {
  const key1 = await C.importAesKey(zeroKeyBytes);
  const key2 = await C.importAesKey(new Uint8Array(32).fill(7));
  const blob = await C.encryptMessage(key1, "secret");
  await assert.rejects(() => C.decryptMessage(key2, blob));
});

test("a tampered message fails to decrypt", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const blob = await C.encryptMessage(key, "secret");
  const bytes = C.base64ToBytes(blob.slice(5));
  bytes[bytes.length - 1] ^= 1;
  const tampered = "GPV2:" + C.bytesToBase64(bytes);
  await assert.rejects(() => C.decryptMessage(key, tampered));
});

test("too-short and wrong-prefix messages are rejected", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  await assert.rejects(() => C.decryptMessage(key, "GPV2:AAAA"));
  await assert.rejects(() => C.decryptMessage(key, "HELLO:AAAA"));
});

test("a key that is not 32 bytes is rejected", async () => {
  await assert.rejects(() => C.importAesKey(new Uint8Array(16)));
});

test("base64 helpers round-trip, including large inputs", () => {
  const big = new Uint8Array(300000).map((_, i) => i % 256);
  assert.deepEqual(C.base64ToBytes(C.bytesToBase64(big)), big);
});

test("same passphrase gives the same key; different passphrase or threadId differs", async () => {
  const a = await C.deriveKeyFromPassphrase("correct horse battery");
  const b = await C.deriveKeyFromPassphrase("  correct horse battery  ");
  const c = await C.deriveKeyFromPassphrase("correct horse batterz");
  const d = await C.deriveKeyFromPassphrase("correct horse battery", "thread-999");
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.notDeepEqual(a, d);
  assert.equal(a.length, 32);
});

test("passphrase key works for a full encrypt/decrypt round trip", async () => {
  const bytes = await C.deriveKeyFromPassphrase("shared secret phrase");
  const key = await C.importAesKey(bytes);
  assert.equal(await C.decryptMessage(key, await C.encryptMessage(key, "hi")), "hi");
});

test("generated passphrases have the right shape and are not repeated", () => {
  const p1 = C.generatePassphrase();
  const p2 = C.generatePassphrase();
  assert.match(p1, /^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$/);
  assert.notEqual(p1, p2);
});

test("NIST FIPS 203 ML-KEM-768 + ECDH P-256 hybrid key exchange strictly requires ML-KEM-768 secret and rejects tampered ciphertexts", async () => {
  const alice = await C.generateIdentity();
  const bob = await C.generateIdentity();

  assert.equal(alice.quantumSafe, true);
  assert.equal(bob.quantumSafe, true);
  assert.equal(C.base64ToBytes(alice.publicKey).length, C.HYBRID_PUB_BYTES); // 1249 bytes (65 P-256 + 1184 ML-KEM-768 ek)

  // Calling deriveSharedKey without the ML-KEM-768 shared secret MUST throw!
  await assert.rejects(
    () => C.deriveSharedKey(alice.privateJwk, alice.publicKey, bob.publicKey),
    /requires a 32-byte ML-KEM-768 shared secret/
  );

  // Bob encapsulates a 256-bit secret to Alice's NIST FIPS 203 ML-KEM-768 public key
  const { ciphertextB64, sharedSecret: bobPqSecret } = await C.pqEncapsulate(alice.publicKey);
  assert.equal(C.base64ToBytes(ciphertextB64).length, C.MLKEM_CT_BYTES); // 1088 bytes

  // Alice decapsulates the ML-KEM-768 ciphertext using her 2400-byte decapsulation key
  const alicePqSecret = await C.pqDecapsulate(alice.privateJwk, ciphertextB64);
  assert.deepEqual(alicePqSecret, bobPqSecret);

  // Verify Fujisaki-Okamoto implicit rejection: flipping 1 bit in ML-KEM-768 ciphertext produces a pseudorandomly different secret!
  const ctBytes = C.base64ToBytes(ciphertextB64);
  ctBytes[10] ^= 1;
  const implicitRejectedSecret = await C.pqDecapsulate(alice.privateJwk, C.bytesToBase64(ctBytes));
  assert.notDeepEqual(implicitRejectedSecret, bobPqSecret, "Fujisaki-Okamoto implicit rejection rejects tampered KEM ciphertext");

  const aliceKey = await C.deriveSharedKey(alice.privateJwk, alice.publicKey, bob.publicKey, alicePqSecret);
  const bobKey = await C.deriveSharedKey(bob.privateJwk, bob.publicKey, alice.publicKey, bobPqSecret);
  assert.deepEqual(aliceKey, bobKey);

  const codeA = await C.safetyCode(alice.publicKey, bob.publicKey);
  const codeB = await C.safetyCode(bob.publicKey, alice.publicKey);
  assert.equal(codeA, codeB);
  assert.match(codeA, /^([0-9A-F]{4} ){4}[0-9A-F]{4}$/);
});

test("multi-packet ML-KEM-768 key framing fits every packet under 1000 characters and reassembles cleanly", async () => {
  const alice = await C.generateIdentity();
  const bob = await C.generateIdentity();
  const { ciphertextB64 } = await C.pqEncapsulate(alice.publicKey);

  const packets = C.makeKeyPackets(bob.publicKey, ciphertextB64);
  assert.ok(packets.length >= 2);
  for (const pkt of packets) {
    assert.ok(pkt.length < 1000, `Packet length ${pkt.length} must be < 1000`);
  }

  const reassembled = C.reassembleKeyPackets(packets);
  assert.equal(reassembled.length, 1);
  assert.equal(reassembled[0].publicKeyB64, bob.publicKey);
  assert.equal(reassembled[0].kemCiphertextB64, ciphertextB64);
  assert.equal(reassembled[0].quantumSafe, true);
});

test("key exchange: a third party gets a different key and cannot decrypt", async () => {
  const alice = await C.generateIdentity();
  const bob = await C.generateIdentity();
  const eve = await C.generateIdentity();

  const { ciphertextB64, sharedSecret } = await C.pqEncapsulate(alice.publicKey);
  const alicePq = await C.pqDecapsulate(alice.privateJwk, ciphertextB64);

  const aliceBob = await C.importAesKey(
    await C.deriveSharedKey(alice.privateJwk, alice.publicKey, bob.publicKey, alicePq)
  );
  const eveKey = await C.importAesKey(
    await C.deriveSharedKey(eve.privateJwk, eve.publicKey, alice.publicKey, sharedSecret)
  );
  const blob = await C.encryptMessage(aliceBob, "for bob only");
  await assert.rejects(() => C.decryptMessage(eveKey, blob));
});

test("key exchange: a malformed public key is rejected", async () => {
  const alice = await C.generateIdentity();
  const junk = C.bytesToBase64(new Uint8Array(65).fill(1));
  await assert.rejects(() => C.deriveSharedKey(alice.privateJwk, alice.publicKey, junk));
});

test("encrypted output size matches the documented overhead", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const blob = await C.encryptMessage(key, "hi");
  assert.equal(blob.length, 5 + 40);
});

test("block-padded messages hide exact length and round-trip cleanly", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const shortBlob = await C.encryptMessage(key, "a", { pad: true });
  const medBlob = await C.encryptMessage(key, "hello world!", { pad: true });
  assert.equal(shortBlob.length, medBlob.length);
  assert.equal(await C.decryptMessage(key, shortBlob), "a");
  assert.equal(await C.decryptMessage(key, medBlob), "hello world!");
});

test("v5 authenticated envelopes bind sequence numbers, timestamps, and AAD", async () => {
  const key = await C.importAesKey(zeroKeyBytes);
  const blob = await C.encryptMessage(key, "envelope message", {
    pad: true,
    aad: "thread:777",
    envelope: { seq: 42, ts: 1700000000000, id: "msg-42" },
  });
  const res = await C.decryptMessage(key, blob, { aad: "thread:777", returnEnvelope: true });
  assert.equal(res.text, "envelope message");
  assert.equal(res.envelope.seq, 42);
  assert.equal(res.envelope.id, "msg-42");
  await assert.rejects(() => C.decryptMessage(key, blob, { aad: "thread:wrong" }));
});

test("destructive forward-secrecy HMAC chain ratchet overwrites chain key and isolates past message keys", async () => {
  const initialChainKey = new Uint8Array(32).fill(9);
  const step1 = await C.ratchetChainStep(initialChainKey, 1, "thread:1");
  const step2 = await C.ratchetChainStep(step1.nextChainKeyBytes, 2, "thread:1");

  assert.notDeepEqual(step1.nextChainKeyBytes, initialChainKey);
  assert.notDeepEqual(step2.messageKeyBytes, step1.messageKeyBytes);

  const msg1Blob = await C.encryptMessage(step1.messageAesKey, "msg 1");
  assert.equal(await C.decryptMessage(step1.messageAesKey, msg1Blob), "msg 1");
  // Even if an attacker compromises step2's chain key later, step2's message key cannot decrypt msg 1!
  await assert.rejects(() => C.decryptMessage(step2.messageAesKey, msg1Blob));
});

test("Vault encryption at rest seals and unseals keys with master passphrase", async () => {
  const payload = { "conv:111": { mode: "passphrase", keyB64: "ABCD" } };
  const envelope = await C.sealVaultData("master-passphrase-12345", payload);
  const restored = await C.unsealVaultData("master-passphrase-12345", envelope);
  assert.deepEqual(restored, payload);
  await assert.rejects(() => C.unsealVaultData("wrong-passphrase-00000", envelope));
});
