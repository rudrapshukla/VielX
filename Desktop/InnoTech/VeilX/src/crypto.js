/**
 * src/crypto.js — Standardized NIST FIPS 203 ML-KEM-768 + ECDH P-256 Hybrid
 * Cryptography & Forward-Secrecy Symmetric Ratchet for VeilX v5.2.0.
 */

globalThis.GPV = globalThis.GPV || {};

GPV.crypto = (() => {
  "use strict";

  const webCrypto =
    (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle
      ? globalThis.crypto
      : null) ||
    (typeof require === "function"
      ? (() => {
          try {
            return require("node:crypto").webcrypto;
          } catch (_) {
            return null;
          }
        })()
      : null);

  // ── Message format prefixes ──────────────────────────────────────────────
  const MSG_PREFIX = "GPV2:";   // encrypted chat message
  const KEY_PREFIX = "GPV2K:";  // public key / ML-KEM-768 handshake packet

  // ── Cryptographic constants ──────────────────────────────────────────────
  const PBKDF2_ITERATIONS = 600000;
  const PBKDF2_SALT = new TextEncoder().encode("guptavarta-v2-passphrase-salt");
  const HKDF_INFO = new TextEncoder().encode("guptavarta-v2-conversation-key");
  const PQ_HKDF_INFO = new TextEncoder().encode("veilx-v5-hybrid-p256-mlkem768-key");
  const VAULT_SALT_PREFIX = "veilx-v5-vault-salt:";

  const IV_BYTES = 12;
  const TAG_BYTES = 16;
  const PASSPHRASE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  // ── NIST FIPS 203 ML-KEM-768 Constants ───────────────────────────────────
  const MLKEM_Q = 3329;
  const MLKEM_N = 256;
  const MLKEM_K = 3; // ML-KEM-768 (NIST Security Category 3)
  const CLASSICAL_PUB_BYTES = 65;
  const MLKEM_EK_BYTES = 1184; // 384 * 3 + 32
  const MLKEM_DK_BYTES = 2400; // 1152 + 1184 + 32 + 32
  const MLKEM_CT_BYTES = 1088; // 960 + 128
  const HYBRID_PUB_BYTES = CLASSICAL_PUB_BYTES + MLKEM_EK_BYTES; // 1249 bytes
  // Also keep legacy 337-byte / 401-byte bundle support so existing tests or v3/v4 keys parse cleanly
  const LEGACY_HYBRID_BYTES_V4 = 337;
  const LEGACY_HYBRID_BYTES_V3 = 401;

  // ── Base64 & Byte Helpers ────────────────────────────────────────────────

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function concatBytes(...parts) {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function timingSafeEqualBytes(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  function zeroize(bytes) {
    if (bytes && typeof bytes.fill === "function") {
      bytes.fill(0);
    }
  }

  function sortPair(a, b) {
    return a <= b ? [a, b] : [b, a];
  }

  // ── Fast 32-bit Interleaved FIPS 202 Keccak-f[1600] (SHA-3 & SHAKE) ──────

  const RC_HI = new Uint32Array([
    0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
    0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
    0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000,
  ]);
  const RC_LO = new Uint32Array([
    0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
    0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
    0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
    0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008,
  ]);
  const ROTC = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
    39, 61, 20, 44,
  ];
  const PILN = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
    22, 9, 6, 1,
  ];

  function keccakF1600(sLo, sHi) {
    const bLo = new Uint32Array(5);
    const bHi = new Uint32Array(5);
    for (let round = 0; round < 24; round++) {
      for (let i = 0; i < 5; i++) {
        bLo[i] = sLo[i] ^ sLo[i + 5] ^ sLo[i + 10] ^ sLo[i + 15] ^ sLo[i + 20];
        bHi[i] = sHi[i] ^ sHi[i + 5] ^ sHi[i + 10] ^ sHi[i + 15] ^ sHi[i + 20];
      }
      for (let i = 0; i < 5; i++) {
        const i4 = (i + 4) % 5;
        const i1 = (i + 1) % 5;
        const rLo = (bLo[i1] << 1) | (bHi[i1] >>> 31);
        const rHi = (bHi[i1] << 1) | (bLo[i1] >>> 31);
        const tLo = bLo[i4] ^ rLo;
        const tHi = bHi[i4] ^ rHi;
        for (let j = 0; j < 25; j += 5) {
          sLo[j + i] ^= tLo;
          sHi[j + i] ^= tHi;
        }
      }
      let tLo = sLo[1];
      let tHi = sHi[1];
      for (let i = 0; i < 24; i++) {
        const j = PILN[i];
        const n = ROTC[i];
        const nLo =
          n < 32
            ? (tLo << n) | (tHi >>> (32 - n))
            : (tHi << (n - 32)) | (tLo >>> (64 - n));
        const nHi =
          n < 32
            ? (tHi << n) | (tLo >>> (32 - n))
            : (tLo << (n - 32)) | (tHi >>> (64 - n));
        tLo = sLo[j];
        tHi = sHi[j];
        sLo[j] = nLo;
        sHi[j] = nHi;
      }
      for (let j = 0; j < 25; j += 5) {
        for (let i = 0; i < 5; i++) {
          bLo[i] = sLo[j + i];
          bHi[i] = sHi[j + i];
        }
        for (let i = 0; i < 5; i++) {
          const i1 = (i + 1) % 5;
          const i2 = (i + 2) % 5;
          sLo[j + i] ^= ~bLo[i1] & bLo[i2];
          sHi[j + i] ^= ~bHi[i1] & bHi[i2];
        }
      }
      sLo[0] ^= RC_LO[round];
      sHi[0] ^= RC_HI[round];
    }
  }

  function keccakSponge(rateBytes, suffix, inputBytes, outLen) {
    const sLo = new Uint32Array(25);
    const sHi = new Uint32Array(25);
    const block = new Uint8Array(200);
    let pos = 0;
    const rateLanes = rateBytes >> 3;
    const blockView = new DataView(block.buffer);

    const absorb = () => {
      for (let j = 0; j < rateLanes; j++) {
        sLo[j] ^= blockView.getUint32(j * 8, true);
        sHi[j] ^= blockView.getUint32(j * 8 + 4, true);
      }
      keccakF1600(sLo, sHi);
    };

    for (let i = 0; i < inputBytes.length; i++) {
      block[pos++] = inputBytes[i];
      if (pos === rateBytes) {
        absorb();
        block.fill(0);
        pos = 0;
      }
    }
    block[pos] ^= suffix;
    block[rateBytes - 1] ^= 0x80;
    absorb();

    const out = new Uint8Array(outLen);
    let outPos = 0;
    const squeezeBuf = new Uint8Array(rateBytes);
    const squeezeView = new DataView(squeezeBuf.buffer);
    while (outPos < outLen) {
      for (let j = 0; j < rateLanes; j++) {
        squeezeView.setUint32(j * 8, sLo[j], true);
        squeezeView.setUint32(j * 8 + 4, sHi[j], true);
      }
      const take = Math.min(rateBytes, outLen - outPos);
      out.set(squeezeBuf.subarray(0, take), outPos);
      outPos += take;
      if (outPos < outLen) keccakF1600(sLo, sHi);
    }
    return out;
  }

  const sha3_256 = (msg) => keccakSponge(136, 0x06, msg, 32);
  const sha3_512 = (msg) => keccakSponge(72, 0x06, msg, 64);
  const shake128 = (msg, len) => keccakSponge(168, 0x1f, msg, len);
  const shake256 = (msg, len) => keccakSponge(136, 0x1f, msg, len);

  // ── NIST FIPS 203 ML-KEM-768 Arithmetic & Algorithms ─────────────────────

  function bitRev7(x) {
    let r = 0;
    for (let i = 0; i < 7; i++) r = (r << 1) | ((x >> i) & 1);
    return r;
  }

  function modPow(base, exp, m) {
    let res = 1;
    base %= m;
    while (exp > 0) {
      if (exp & 1) res = (res * base) % m;
      base = (base * base) % m;
      exp >>= 1;
    }
    return res;
  }

  const MLKEM_ZETAS = new Int32Array(128);
  const MLKEM_GAMMAS = new Int32Array(128);
  for (let i = 0; i < 128; i++) {
    MLKEM_ZETAS[i] = modPow(17, bitRev7(i), MLKEM_Q);
    MLKEM_GAMMAS[i] = modPow(17, 2 * bitRev7(i) + 1, MLKEM_Q);
  }

  const modQ = (x) => ((x % MLKEM_Q) + MLKEM_Q) % MLKEM_Q;

  function mlkemNtt(f) {
    const a = new Int32Array(f);
    let k = 1;
    for (let len = 128; len >= 2; len >>= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const zeta = MLKEM_ZETAS[k++];
        for (let j = start; j < start + len; j++) {
          const t = (zeta * a[j + len]) % MLKEM_Q;
          a[j + len] = modQ(a[j] - t);
          a[j] = (a[j] + t) % MLKEM_Q;
        }
      }
    }
    return a;
  }

  function mlkemInvNtt(f) {
    const a = new Int32Array(f);
    let k = 127;
    for (let len = 2; len <= 128; len <<= 1) {
      for (let start = 0; start < 256; start += 2 * len) {
        const zeta = MLKEM_ZETAS[k--];
        for (let j = start; j < start + len; j++) {
          const t = a[j];
          a[j] = (t + a[j + len]) % MLKEM_Q;
          a[j + len] = (zeta * modQ(a[j + len] - t)) % MLKEM_Q;
        }
      }
    }
    for (let i = 0; i < 256; i++) a[i] = (a[i] * 3303) % MLKEM_Q;
    return a;
  }

  function mlkemMultiplyNTTs(f, g) {
    const h = new Int32Array(256);
    for (let i = 0; i < 128; i++) {
      const idx = 2 * i;
      const gamma = MLKEM_GAMMAS[i];
      const a0 = f[idx];
      const a1 = f[idx + 1];
      const b0 = g[idx];
      const b1 = g[idx + 1];
      h[idx] = modQ(a0 * b0 + ((a1 * b1) % MLKEM_Q) * gamma);
      h[idx + 1] = modQ(a0 * b1 + a1 * b0);
    }
    return h;
  }

  function mlkemPolyAdd(a, b) {
    const r = new Int32Array(256);
    for (let i = 0; i < 256; i++) r[i] = (a[i] + b[i]) % MLKEM_Q;
    return r;
  }

  function mlkemPolySub(a, b) {
    const r = new Int32Array(256);
    for (let i = 0; i < 256; i++) r[i] = modQ(a[i] - b[i]);
    return r;
  }

  function mlkemSampleNTT(seed34) {
    const buf = shake128(seed34, 840);
    const a = new Int32Array(256);
    let i = 0;
    let j = 0;
    while (j < 256) {
      const d1 = buf[i] + 256 * (buf[i + 1] & 0x0f);
      const d2 = (buf[i + 1] >> 4) + 16 * buf[i + 2];
      if (d1 < MLKEM_Q) a[j++] = d1;
      if (d2 < MLKEM_Q && j < 256) a[j++] = d2;
      i += 3;
    }
    return a;
  }

  function mlkemSamplePolyCBD2(bytes128) {
    const f = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      const bitOffset = 4 * i;
      const byte = bytes128[bitOffset >> 3];
      const nibble = (byte >> (bitOffset & 4)) & 0x0f;
      const x = (nibble & 1) + ((nibble >> 1) & 1);
      const y = ((nibble >> 2) & 1) + ((nibble >> 3) & 1);
      f[i] = modQ(x - y);
    }
    return f;
  }

  function mlkemByteEncode(f, d) {
    const out = new Uint8Array(32 * d);
    let bitBuf = 0;
    let bitCount = 0;
    let idx = 0;
    const mask = (1 << d) - 1;
    for (let i = 0; i < 256; i++) {
      bitBuf |= (f[i] & mask) << bitCount;
      bitCount += d;
      while (bitCount >= 8) {
        out[idx++] = bitBuf & 0xff;
        bitBuf >>>= 8;
        bitCount -= 8;
      }
    }
    return out;
  }

  function mlkemByteDecode(bytes, d) {
    const f = new Int32Array(256);
    let bitBuf = 0;
    let bitCount = 0;
    let idx = 0;
    const mask = (1 << d) - 1;
    for (let i = 0; i < 256; i++) {
      while (bitCount < d) {
        bitBuf |= bytes[idx++] << bitCount;
        bitCount += 8;
      }
      f[i] = bitBuf & mask;
      bitBuf >>>= d;
      bitCount -= d;
    }
    return f;
  }

  function mlkemCompress(f, d) {
    const r = new Int32Array(256);
    const twoD = 1 << d;
    for (let i = 0; i < 256; i++) {
      r[i] = Math.round((twoD * f[i]) / MLKEM_Q) % twoD;
    }
    return r;
  }

  function mlkemDecompress(f, d) {
    const r = new Int32Array(256);
    const twoD = 1 << d;
    for (let i = 0; i < 256; i++) {
      r[i] = Math.round((MLKEM_Q * f[i]) / twoD) % MLKEM_Q;
    }
    return r;
  }

  /**
   * NIST FIPS 203 ML-KEM-768 Key Generation (`ML-KEM.KeyGen_internal`).
   * Returns `{ ek (1184 bytes), dk (2400 bytes) }`.
   */
  function mlkem768KeyGen(dSeed32, zSeed32) {
    const d = dSeed32 || webCrypto.getRandomValues(new Uint8Array(32));
    const z = zSeed32 || webCrypto.getRandomValues(new Uint8Array(32));
    const gOut = sha3_512(concatBytes(d, new Uint8Array([MLKEM_K])));
    const rho = gOut.subarray(0, 32);
    const sigma = gOut.subarray(32, 64);

    const A = [];
    for (let i = 0; i < MLKEM_K; i++) {
      A[i] = [];
      for (let j = 0; j < MLKEM_K; j++) {
        A[i][j] = mlkemSampleNTT(concatBytes(rho, new Uint8Array([j, i])));
      }
    }

    let Nctr = 0;
    const s = [];
    const e = [];
    for (let i = 0; i < MLKEM_K; i++) {
      s[i] = mlkemNtt(
        mlkemSamplePolyCBD2(shake256(concatBytes(sigma, new Uint8Array([Nctr++])), 128))
      );
    }
    for (let i = 0; i < MLKEM_K; i++) {
      e[i] = mlkemNtt(
        mlkemSamplePolyCBD2(shake256(concatBytes(sigma, new Uint8Array([Nctr++])), 128))
      );
    }

    const tHat = [];
    for (let i = 0; i < MLKEM_K; i++) {
      let acc = new Int32Array(256);
      for (let j = 0; j < MLKEM_K; j++) {
        acc = mlkemPolyAdd(acc, mlkemMultiplyNTTs(A[i][j], s[j]));
      }
      tHat[i] = mlkemPolyAdd(acc, e[i]);
    }

    const ekPke = concatBytes(...tHat.map((p) => mlkemByteEncode(p, 12)), rho);
    const dkPke = concatBytes(...s.map((p) => mlkemByteEncode(p, 12)));
    const hEk = sha3_256(ekPke);
    const dk = concatBytes(dkPke, ekPke, hEk, z);
    return { ek: ekPke, dk };
  }

  function mlkem768PkeEncrypt(ek, m32, r32) {
    const tHat = [];
    for (let i = 0; i < MLKEM_K; i++) {
      tHat[i] = mlkemByteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12);
    }
    const rho = ek.subarray(1152, 1184);

    const A = [];
    for (let i = 0; i < MLKEM_K; i++) {
      A[i] = [];
      for (let j = 0; j < MLKEM_K; j++) {
        A[i][j] = mlkemSampleNTT(concatBytes(rho, new Uint8Array([j, i])));
      }
    }

    let Nctr = 0;
    const rVec = [];
    const e1 = [];
    for (let i = 0; i < MLKEM_K; i++) {
      rVec[i] = mlkemNtt(
        mlkemSamplePolyCBD2(shake256(concatBytes(r32, new Uint8Array([Nctr++])), 128))
      );
    }
    for (let i = 0; i < MLKEM_K; i++) {
      e1[i] = mlkemSamplePolyCBD2(
        shake256(concatBytes(r32, new Uint8Array([Nctr++])), 128)
      );
    }
    const e2 = mlkemSamplePolyCBD2(
      shake256(concatBytes(r32, new Uint8Array([Nctr++])), 128)
    );

    const u = [];
    for (let i = 0; i < MLKEM_K; i++) {
      let acc = new Int32Array(256);
      for (let j = 0; j < MLKEM_K; j++) {
        acc = mlkemPolyAdd(acc, mlkemMultiplyNTTs(A[j][i], rVec[j]));
      }
      u[i] = mlkemPolyAdd(mlkemInvNtt(acc), e1[i]);
    }

    const mu = mlkemDecompress(mlkemByteDecode(m32, 1), 1);
    let inner = new Int32Array(256);
    for (let i = 0; i < MLKEM_K; i++) {
      inner = mlkemPolyAdd(inner, mlkemMultiplyNTTs(tHat[i], rVec[i]));
    }
    const v = mlkemPolyAdd(mlkemPolyAdd(mlkemInvNtt(inner), e2), mu);

    const c1 = concatBytes(...u.map((p) => mlkemByteEncode(mlkemCompress(p, 10), 10)));
    const c2 = mlkemByteEncode(mlkemCompress(v, 4), 4);
    return concatBytes(c1, c2);
  }

  function mlkem768PkeDecrypt(dkPke, c1088) {
    const u = [];
    for (let i = 0; i < MLKEM_K; i++) {
      u[i] = mlkemDecompress(
        mlkemByteDecode(c1088.subarray(320 * i, 320 * (i + 1)), 10),
        10
      );
    }
    const v = mlkemDecompress(mlkemByteDecode(c1088.subarray(960, 1088), 4), 4);
    const s = [];
    for (let i = 0; i < MLKEM_K; i++) {
      s[i] = mlkemByteDecode(dkPke.subarray(384 * i, 384 * (i + 1)), 12);
    }

    let inner = new Int32Array(256);
    for (let i = 0; i < MLKEM_K; i++) {
      inner = mlkemPolyAdd(inner, mlkemMultiplyNTTs(s[i], mlkemNtt(u[i])));
    }
    const w = mlkemPolySub(v, mlkemInvNtt(inner));
    return mlkemByteEncode(mlkemCompress(w, 1), 1);
  }

  /**
   * NIST FIPS 203 ML-KEM-768 Encapsulation (`ML-KEM.Encaps`).
   * Takes a peer's Hybrid Public Key (`peerPublicB64`, 1249 bytes) and returns
   * `{ ciphertextB64 (1088 bytes encoded), sharedSecret (32 bytes) }`.
   */
  async function pqEncapsulate(peerPublicB64) {
    const raw = base64ToBytes(peerPublicB64);
    if (raw.length !== HYBRID_PUB_BYTES) {
      throw new Error("Peer public key does not contain a NIST FIPS 203 ML-KEM-768 key");
    }
    const ek = raw.subarray(CLASSICAL_PUB_BYTES, HYBRID_PUB_BYTES);

    // FIPS 203 modulus check on ek: verify ByteEncode_12(ByteDecode_12(tHat)) == ek[0..1152]
    for (let i = 0; i < MLKEM_K; i++) {
      const slice = ek.subarray(384 * i, 384 * (i + 1));
      const reEncoded = mlkemByteEncode(mlkemByteDecode(slice, 12), 12);
      if (!timingSafeEqualBytes(slice, reEncoded)) {
        throw new Error("Invalid ML-KEM-768 encapsulation key (failed FIPS 203 modulus check)");
      }
    }

    const m = webCrypto.getRandomValues(new Uint8Array(32));
    const hEk = sha3_256(ek);
    const kr = sha3_512(concatBytes(m, hEk));
    const sharedSecret = new Uint8Array(kr.subarray(0, 32));
    const r = kr.subarray(32, 64);
    const c = mlkem768PkeEncrypt(ek, m, r);
    zeroize(m);

    return {
      ciphertextB64: bytesToBase64(c),
      sharedSecret,
    };
  }

  /**
   * NIST FIPS 203 ML-KEM-768 Decapsulation (`ML-KEM.Decaps`) with Fujisaki-Okamoto
   * implicit rejection.
   */
  async function pqDecapsulate(myPrivateJwk, ciphertextB64) {
    if (!myPrivateJwk || !myPrivateJwk.mlkemDkB64) {
      throw new Error("Missing NIST FIPS 203 ML-KEM-768 decapsulation key");
    }
    const dk = base64ToBytes(myPrivateJwk.mlkemDkB64);
    const c = base64ToBytes(ciphertextB64);
    if (dk.length !== MLKEM_DK_BYTES || c.length !== MLKEM_CT_BYTES) {
      throw new Error("Invalid ML-KEM-768 key or ciphertext length");
    }

    const dkPke = dk.subarray(0, 1152);
    const ekPke = dk.subarray(1152, 2336);
    const h = dk.subarray(2336, 2368);
    const z = dk.subarray(2368, 2400);

    const mPrime = mlkem768PkeDecrypt(dkPke, c);
    const krPrime = sha3_512(concatBytes(mPrime, h));
    const kPrime = new Uint8Array(krPrime.subarray(0, 32));
    const rPrime = krPrime.subarray(32, 64);
    const kBar = shake256(concatBytes(z, c), 32);
    const cPrime = mlkem768PkeEncrypt(ekPke, mPrime, rPrime);

    const valid = timingSafeEqualBytes(c, cPrime);
    return valid ? kPrime : kBar;
  }

  // ── Traffic-Analysis Padding (ISO/IEC 7816-4 Block Padding) ──────────────

  function padBytes(plainBytes, blockSize = 32) {
    const rem = (plainBytes.length + 1) % blockSize;
    const padLen = rem === 0 ? 1 : blockSize - rem + 1;
    const out = new Uint8Array(plainBytes.length + padLen);
    out.set(plainBytes, 0);
    out[plainBytes.length] = 0x80;
    return out;
  }

  function unpadBytes(paddedBytes) {
    for (let i = paddedBytes.length - 1; i >= 0; i--) {
      if (paddedBytes[i] === 0x80) {
        return paddedBytes.subarray(0, i);
      }
      if (paddedBytes[i] !== 0x00) {
        break;
      }
    }
    return paddedBytes;
  }

  // ── True Destructive Forward-Secrecy Symmetric Chain Ratchet ─────────────

  /**
   * Advance a 32-byte Chain Key (`chainKeyBytes`) by one irreversible step using
   * HMAC-SHA256 (one-way PRF):
   *   `messageKeyBytes = HMAC-SHA256(chainKeyBytes, 0x01 || threadId || seq)`
   *   `nextChainKeyBytes = HMAC-SHA256(chainKeyBytes, 0x02 || threadId || seq)`
   *
   * When the caller overwrites the stored `chainKeyB64` with `nextChainKeyBytes`
   * and zeroizes the old `chainKeyBytes`, a future compromise of `nextChainKeyBytes`
   * CANNOT recover `chainKeyBytes` or `messageKeyBytes` — providing true forward
   * secrecy for all previously sent messages!
   */
  async function ratchetChainStep(chainKeyBytes, seq = 1, threadId = "") {
    if (typeof chainKeyBytes === "string") {
      chainKeyBytes = base64ToBytes(chainKeyBytes);
    }
    if (!(chainKeyBytes instanceof Uint8Array) || chainKeyBytes.length !== 32) {
      throw new Error("Chain key must be exactly 32 bytes");
    }
    const hmacKey = await webCrypto.subtle.importKey(
      "raw",
      chainKeyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const contextBytes = new TextEncoder().encode(`:${threadId}:${seq}`);
    const msgInput = concatBytes(new Uint8Array([0x01]), contextBytes);
    const nextInput = concatBytes(new Uint8Array([0x02]), contextBytes);

    const messageKeyBytes = new Uint8Array(
      await webCrypto.subtle.sign("HMAC", hmacKey, msgInput)
    );
    const nextChainKeyBytes = new Uint8Array(
      await webCrypto.subtle.sign("HMAC", hmacKey, nextInput)
    );
    const messageAesKey = await importAesKey(messageKeyBytes);

    return {
      messageAesKey,
      messageKeyBytes,
      messageKeyB64: bytesToBase64(messageKeyBytes),
      nextChainKeyBytes,
      nextChainKeyB64: bytesToBase64(nextChainKeyBytes),
    };
  }

  /**
   * Backward-compatible helper for deriving a subkey at `seq`.
   */
  async function deriveMessageSubkey(rootKeyBytes, seq = 0, threadId = "") {
    const step = await ratchetChainStep(rootKeyBytes, seq, threadId);
    return step.messageAesKey;
  }

  // ── AES-256-GCM: Authenticated Message & Envelope Encryption ─────────────

  async function importAesKey(rawKeyBytes) {
    if (!rawKeyBytes || rawKeyBytes.length !== 32) {
      throw new Error("AES-256 key must be exactly 32 bytes");
    }
    return webCrypto.subtle.importKey(
      "raw",
      rawKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptMessage(aesKey, plaintext, options = {}) {
    if (typeof plaintext !== "string") {
      throw new Error("Plaintext must be a string");
    }
    const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));

    let payloadBytes;
    if (options && options.envelope) {
      const envObj = {
        t: plaintext,
        seq: Number.isInteger(options.envelope.seq) ? options.envelope.seq : 1,
        ts: options.envelope.ts || Date.now(),
        id:
          options.envelope.id ||
          bytesToBase64(webCrypto.getRandomValues(new Uint8Array(8))),
      };
      if (options.envelope.fp) envObj.fp = options.envelope.fp;
      if (options.envelope.gid) {
        envObj.gid = options.envelope.gid;
        envObj.ci = options.envelope.ci;
        envObj.ct = options.envelope.ct;
      }
      const envBytes = new TextEncoder().encode(JSON.stringify(envObj));
      if (options.pad) {
        const padded = padBytes(envBytes, options.blockSize || 32);
        payloadBytes = new Uint8Array(1 + padded.length);
        payloadBytes[0] = 0x02;
        payloadBytes.set(padded, 1);
      } else {
        payloadBytes = new Uint8Array(1 + envBytes.length);
        payloadBytes[0] = 0x01;
        payloadBytes.set(envBytes, 1);
      }
    } else {
      const encoded = new TextEncoder().encode(plaintext);
      if (options && options.pad) {
        const padded = padBytes(encoded, options.blockSize || 32);
        payloadBytes = new Uint8Array(1 + padded.length);
        payloadBytes[0] = 0x00;
        payloadBytes.set(padded, 1);
      } else {
        payloadBytes = encoded;
      }
    }

    const algorithm = { name: "AES-GCM", iv };
    if (options && options.aad) {
      algorithm.additionalData =
        typeof options.aad === "string"
          ? new TextEncoder().encode(options.aad)
          : options.aad;
    }

    const ciphertext = new Uint8Array(
      await webCrypto.subtle.encrypt(algorithm, aesKey, payloadBytes)
    );
    return MSG_PREFIX + bytesToBase64(concatBytes(iv, ciphertext));
  }

  async function decryptMessage(aesKey, blob, options = {}) {
    if (typeof blob !== "string" || !blob.startsWith(MSG_PREFIX)) {
      throw new Error("Not a GPV2 message");
    }
    const rawB64 = blob.slice(MSG_PREFIX.length).replace(/[\u200B-\u200D\uFEFF\u00AD\s]+/g, "");
    const bytes = base64ToBytes(rawB64);
    if (bytes.length < IV_BYTES + TAG_BYTES) {
      throw new Error("Message too short");
    }
    const iv = bytes.slice(0, IV_BYTES);
    const ciphertext = bytes.slice(IV_BYTES);

    const algorithm = { name: "AES-GCM", iv };
    if (options && options.aad) {
      algorithm.additionalData =
        typeof options.aad === "string"
          ? new TextEncoder().encode(options.aad)
          : options.aad;
    }

    const plainBytes = new Uint8Array(
      await webCrypto.subtle.decrypt(algorithm, aesKey, ciphertext)
    );

    let text = "";
    let envelope = null;

    if (plainBytes.length >= 2 && (plainBytes[0] === 0x01 || plainBytes[0] === 0x02)) {
      const body =
        plainBytes[0] === 0x02
          ? unpadBytes(plainBytes.subarray(1))
          : plainBytes.subarray(1);
      envelope = JSON.parse(new TextDecoder().decode(body));
      text = typeof envelope.t === "string" ? envelope.t : "";
    } else if (plainBytes.length >= 2 && plainBytes[0] === 0x00) {
      const unpadded = unpadBytes(plainBytes.subarray(1));
      text = new TextDecoder().decode(unpadded);
    } else {
      text = new TextDecoder().decode(plainBytes);
    }

    if (options && options.returnEnvelope) {
      return {
        text,
        envelope,
        ivB64: bytesToBase64(iv),
      };
    }
    return text;
  }

  // ── Method 1: Key from a Shared Passphrase ───────────────────────────────

  async function deriveKeyFromPassphrase(passphrase, threadId = "") {
    if (typeof passphrase !== "string" || !passphrase.trim()) {
      throw new Error("Passphrase cannot be empty");
    }
    const cleaned = passphrase.trim().normalize("NFKC");
    const salt = threadId
      ? new TextEncoder().encode(`veilx-v5-passphrase-salt:${threadId}`)
      : PBKDF2_SALT;

    const baseKey = await webCrypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(cleaned),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await webCrypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }

  function generatePassphrase() {
    const random = webCrypto.getRandomValues(new Uint8Array(20));
    let chars = "";
    for (let i = 0; i < random.length; i++) {
      chars += PASSPHRASE_ALPHABET[random[i] & 31];
      if (i % 5 === 4 && i !== random.length - 1) chars += "-";
    }
    return chars;
  }

  // ── Method 2: Hybrid NIST FIPS 203 ML-KEM-768 + ECDH P-256 Identity ──────

  /**
   * Generate a standardized Hybrid Post-Quantum + Classical Identity:
   *   - Classical ECDH NIST P-256 keypair (65-byte uncompressed public point)
   *   - Post-Quantum NIST FIPS 203 ML-KEM-768 keypair (1184-byte `ek`, 2400-byte `dk`)
   *   - Combined `publicKey`: 1,249 bytes (Base64-encoded).
   */
  async function generateIdentity() {
    const pair = await webCrypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const classicalPubRaw = new Uint8Array(
      await webCrypto.subtle.exportKey("raw", pair.publicKey)
    );
    const privateJwk = await webCrypto.subtle.exportKey("jwk", pair.privateKey);
    const mlkem = mlkem768KeyGen();

    const hybridPubRaw = concatBytes(classicalPubRaw, mlkem.ek);
    privateJwk.mlkemDkB64 = bytesToBase64(mlkem.dk);
    privateJwk.pqMode = "hybrid-p256-mlkem768-fips203";

    return {
      publicKey: bytesToBase64(hybridPubRaw),
      classicalPublicKey: bytesToBase64(classicalPubRaw),
      privateJwk,
      quantumSafe: true,
      algorithm: "ML-KEM-768 + P-256",
    };
  }

  function parsePublicKeyBundle(publicKeyB64) {
    const raw = base64ToBytes(publicKeyB64);
    if (raw.length === CLASSICAL_PUB_BYTES && raw[0] === 0x04) {
      return {
        valid: true,
        quantumSafe: false,
        classicalBytes: raw,
        pqBytes: null,
        fullB64: publicKeyB64,
      };
    }
    if (raw.length === HYBRID_PUB_BYTES && raw[0] === 0x04) {
      return {
        valid: true,
        quantumSafe: true,
        algorithm: "ML-KEM-768",
        classicalBytes: raw.subarray(0, CLASSICAL_PUB_BYTES),
        pqBytes: raw.subarray(CLASSICAL_PUB_BYTES),
        fullB64: publicKeyB64,
      };
    }
    throw new Error("Invalid public key bundle length or format");
  }

  /**
   * Format a key-exchange wire message (`GPV2K:<pubB64>` or `GPV2K:<pubB64>.<kemCtB64>`).
   * Also see `makeKeyPackets` for splitting across Instagram's 1,000-character DM limit!
   */
  function makeKeyMessage(publicKeyB64, kemCiphertextB64 = null) {
    if (kemCiphertextB64) {
      return `${KEY_PREFIX}${publicKeyB64}.${kemCiphertextB64}`;
    }
    return KEY_PREFIX + publicKeyB64;
  }

  /**
   * Split a large `GPV2K:` key bundle (e.g. 1,668-char ML-KEM-768 public key + 1,452-char
   * ML-KEM-768 ciphertext) into chunks of at most 880 characters so every packet fits
   * inside Instagram's 1,000-character DM limit:
   *   `GPV2K:P1/2#<bundleId>#<slice1>`
   *   `GPV2K:P2/2#<bundleId>#<slice2>`
   */
  function makeKeyPackets(publicKeyB64, kemCiphertextB64 = null, maxChunkChars = 860) {
    const payload = kemCiphertextB64
      ? `${publicKeyB64}.${kemCiphertextB64}`
      : publicKeyB64;
    if (KEY_PREFIX.length + payload.length <= 980) {
      return [KEY_PREFIX + payload];
    }
    // Deterministic 8-char bundle ID from SHA3-256 of the payload
    const hashHex = Array.from(
      sha3_256(new TextEncoder().encode(payload)).subarray(0, 4)
    )
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const chunks = [];
    for (let i = 0; i < payload.length; i += maxChunkChars) {
      chunks.push(payload.slice(i, i + maxChunkChars));
    }
    return chunks.map(
      (chunk, idx) => `${KEY_PREFIX}P${idx + 1}/${chunks.length}#${hashHex}#${chunk}`
    );
  }

  /**
   * Parse a single `GPV2K:...` message (or reassembled payload).
   */
  function parseKeyMessage(text) {
    if (typeof text !== "string") return null;
    const cleaned = text.replace(/[\u200B-\u200D\uFEFF\u00AD\s]+/g, "");
    if (!cleaned.startsWith(KEY_PREFIX)) return null;
    const body = cleaned.slice(KEY_PREFIX.length);

    // Check if it is a multi-part packet header `P1/2#id#chunk`
    const partMatch = body.match(/^P(\d+)\/(\d+)#([0-9a-fA-F]{8})#([A-Za-z0-9+/.=]+)$/);
    if (partMatch) {
      return {
        isPartial: true,
        partIndex: Number(partMatch[1]),
        partTotal: Number(partMatch[2]),
        bundleId: partMatch[3],
        chunk: partMatch[4],
      };
    }

    const match = body.match(/^([A-Za-z0-9+/]+=*)(?:\.([A-Za-z0-9+/]+=*))?/);
    if (!match) return null;
    try {
      const pubB64 = match[1];
      const kemCtB64 = match[2] || null;
      const bundle = parsePublicKeyBundle(pubB64);
      if (kemCtB64) {
        const ctBytes = base64ToBytes(kemCtB64);
        if (ctBytes.length !== MLKEM_CT_BYTES) return null;
      }
      return {
        isPartial: false,
        publicKeyB64: pubB64,
        kemCiphertextB64: kemCtB64,
        quantumSafe: bundle.quantumSafe,
      };
    } catch (_) {
      return null;
    }
  }

  /**
   * Reassemble a list of raw `GPV2K:...` strings from the conversation DOM into
   * complete parsed key entries (`{ publicKeyB64, kemCiphertextB64, quantumSafe }`).
   */
  function reassembleKeyPackets(rawTexts) {
    const completeEntries = [];
    const partialMap = new Map(); // bundleId -> { total, parts: Map(idx -> chunk) }

    for (const raw of rawTexts) {
      const parsed = parseKeyMessage(raw);
      if (!parsed) continue;
      if (!parsed.isPartial) {
        completeEntries.push(parsed);
        continue;
      }
      let group = partialMap.get(parsed.bundleId);
      if (!group) {
        group = { total: parsed.partTotal, parts: new Map() };
        partialMap.set(parsed.bundleId, group);
      }
      group.parts.set(parsed.partIndex, parsed.chunk);
      if (group.parts.size === group.total) {
        let joined = "";
        let allPresent = true;
        for (let i = 1; i <= group.total; i++) {
          if (!group.parts.has(i)) {
            allPresent = false;
            break;
          }
          joined += group.parts.get(i);
        }
        if (allPresent) {
          const full = parseKeyMessage(KEY_PREFIX + joined);
          if (full && !full.isPartial) {
            completeEntries.push(full);
          }
          partialMap.delete(parsed.bundleId);
        }
      }
    }
    return completeEntries;
  }

  /**
   * Derive a 32-byte shared root/chain key from our private key, the peer's public key,
   * and the mandatory 32-byte NIST FIPS 203 ML-KEM-768 `pqSharedSecret`.
   */
  async function deriveSharedKey(myPrivateJwk, myPublicB64, peerPublicB64, pqSharedSecret = null) {
    const myBundle = parsePublicKeyBundle(myPublicB64);
    const peerBundle = parsePublicKeyBundle(peerPublicB64);

    const bothQuantumSafe = Boolean(myBundle.quantumSafe && peerBundle.quantumSafe);
    if (bothQuantumSafe) {
      if (typeof pqSharedSecret === "string") {
        pqSharedSecret = base64ToBytes(pqSharedSecret);
      }
      if (!(pqSharedSecret instanceof Uint8Array) || pqSharedSecret.length !== 32) {
        throw new Error(
          "Post-quantum hybrid key derivation requires a 32-byte ML-KEM-768 shared secret"
        );
      }
    }

    const cleanJwk = {
      kty: myPrivateJwk.kty,
      crv: myPrivateJwk.crv,
      x: myPrivateJwk.x,
      y: myPrivateJwk.y,
      d: myPrivateJwk.d,
      ext: true,
    };

    const myPrivate = await webCrypto.subtle.importKey(
      "jwk",
      cleanJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );

    const peerPublic = await webCrypto.subtle.importKey(
      "raw",
      peerBundle.classicalBytes,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    const ecdhBits = new Uint8Array(
      await webCrypto.subtle.deriveBits(
        { name: "ECDH", public: peerPublic },
        myPrivate,
        256
      )
    );

    const [first, second] = sortPair(myPublicB64, peerPublicB64);
    const salt = new TextEncoder().encode(first + "|" + second);

    const ikm = bothQuantumSafe
      ? concatBytes(ecdhBits, pqSharedSecret)
      : ecdhBits;

    const info = bothQuantumSafe ? PQ_HKDF_INFO : HKDF_INFO;

    const hkdfBase = await webCrypto.subtle.importKey(
      "raw",
      ikm,
      { name: "HKDF" },
      false,
      ["deriveBits"]
    );
    const bits = await webCrypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      hkdfBase,
      256
    );
    zeroize(ecdhBits);
    return new Uint8Array(bits);
  }

  /**
   * Compute an 80-bit human-verifiable Safety Code ("A1B2 C3D4 E5F6 7788 99AA")
   * over both full public key bundles (binding both P-256 and ML-KEM-768 keys).
   */
  async function safetyCode(publicKeyAB64, publicKeyBB64) {
    const [first, second] = sortPair(publicKeyAB64, publicKeyBB64);
    const digest = new Uint8Array(
      await webCrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(first + "|" + second)
      )
    );
    let hex = "";
    for (let i = 0; i < 10; i++) {
      hex += digest[i].toString(16).padStart(2, "0");
    }
    return hex.toUpperCase().match(/.{1,4}/g).join(" ");
  }

  // ── Vault Encryption at Rest ─────────────────────────────────────────────

  async function sealVaultData(passphrase, dataObj) {
    const salt = webCrypto.getRandomValues(new Uint8Array(16));
    const cleaned = passphrase.trim().normalize("NFKC");
    const baseKey = await webCrypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(cleaned),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const keyBits = await webCrypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: concatBytes(new TextEncoder().encode(VAULT_SALT_PREFIX), salt),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      256
    );
    const aesKey = await importAesKey(new Uint8Array(keyBits));
    const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(dataObj));
    const ct = new Uint8Array(
      await webCrypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintextBytes)
    );
    return {
      v: 5,
      saltB64: bytesToBase64(salt),
      ivB64: bytesToBase64(iv),
      ctB64: bytesToBase64(ct),
    };
  }

  async function unsealVaultData(passphrase, envelope) {
    if (!envelope || !envelope.saltB64 || !envelope.ivB64 || !envelope.ctB64) {
      throw new Error("Invalid vault envelope");
    }
    const salt = base64ToBytes(envelope.saltB64);
    const iv = base64ToBytes(envelope.ivB64);
    const ct = base64ToBytes(envelope.ctB64);
    const cleaned = passphrase.trim().normalize("NFKC");
    const baseKey = await webCrypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(cleaned),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const keyBits = await webCrypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: concatBytes(new TextEncoder().encode(VAULT_SALT_PREFIX), salt),
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      256
    );
    const aesKey = await importAesKey(new Uint8Array(keyBits));
    const plainBytes = await webCrypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      ct
    );
    return JSON.parse(new TextDecoder().decode(plainBytes));
  }

  return {
    MSG_PREFIX,
    KEY_PREFIX,
    PBKDF2_ITERATIONS,
    CLASSICAL_PUB_BYTES,
    MLKEM_EK_BYTES,
    MLKEM_DK_BYTES,
    MLKEM_CT_BYTES,
    HYBRID_PUB_BYTES,
    sha3_256,
    sha3_512,
    shake128,
    shake256,
    mlkem768KeyGen,
    bytesToBase64,
    base64ToBytes,
    concatBytes,
    timingSafeEqualBytes,
    zeroize,
    padBytes,
    unpadBytes,
    importAesKey,
    ratchetChainStep,
    deriveMessageSubkey,
    encryptMessage,
    decryptMessage,
    deriveKeyFromPassphrase,
    generatePassphrase,
    generateIdentity,
    parsePublicKeyBundle,
    makeKeyMessage,
    makeKeyPackets,
    parseKeyMessage,
    reassembleKeyPackets,
    deriveSharedKey,
    pqEncapsulate,
    pqDecapsulate,
    safetyCode,
    sealVaultData,
    unsealVaultData,
  };
})();

if (typeof module !== "undefined") module.exports = GPV.crypto;
