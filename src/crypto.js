/**
 * src/crypto.js — VeilX 1.0.0 cryptographic primitives.
 *
 *   • FIPS 202 Keccak (SHA3-256/512, SHAKE128/256), pure JS
 *   • FIPS 203 ML-KEM-768 (KeyGen / Encaps / Decaps), pure JS — cross-checked
 *     against an independent audited implementation (see tests/kat.json)
 *   • WebCrypto wrappers: HKDF-SHA256, HMAC-SHA256, ECDH P-256, AES-256-GCM, PBKDF2
 *   • Passphrase handling and the encrypted-at-rest Vault envelope
 *
 * Protocol logic (handshake, ratchet, wire format) lives in src/protocol.js.
 *
 * NOTE: this is a JavaScript implementation. It is functionally correct, but it
 * is NOT guaranteed constant-time (JS engines give no such guarantee) and it
 * has not been through FIPS 140/CAVP validation.
 */

globalThis.VX = globalThis.VX || {};

VX.crypto = (() => {
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

  const enc = new TextEncoder();

  // ── Constants ────────────────────────────────────────────────────────────
  const PBKDF2_ITERATIONS = 600000;
  const PASSPHRASE_SALT = enc.encode("veilx-v1-passphrase-salt");
  const VAULT_SALT_PREFIX = "veilx-v1-vault-salt:";
  const VAULT_AAD = enc.encode("veilx-v1-vault");

  const IV_BYTES = 12;
  const TAG_BYTES = 16;
  const PASSPHRASE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  // ML-KEM-768 (FIPS 203)
  const MLKEM_Q = 3329;
  const MLKEM_N = 256;
  const MLKEM_K = 3;
  const MLKEM_EK_BYTES = 1184;
  const MLKEM_DK_BYTES = 2400;
  const MLKEM_CT_BYTES = 1088;
  const P256_PUB_BYTES = 65;

  // ── Base64 & Byte Helpers ────────────────────────────────────────────────

  function bytesToBase64(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
    const CHUNK = 0x8000;
    if (u8.length <= CHUNK) {
      return btoa(String.fromCharCode.apply(null, u8));
    }
    const parts = [];
    for (let i = 0; i < u8.length; i += CHUNK) {
      parts.push(String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK)));
    }
    return btoa(parts.join(""));
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

  const K_BLO = new Uint32Array(5);
  const K_BHI = new Uint32Array(5);

  function keccakF1600(sLo, sHi) {
    const bLo = K_BLO;
    const bHi = K_BHI;
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
    // FIPS 203 Algorithm 6: for d = 12 the decoded value is reduced mod q.
    // (This is what makes the encapsulation-key modulus check effective.)
    if (d === 12) {
      for (let i = 0; i < 256; i++) f[i] = f[i] % MLKEM_Q;
    }
    return f;
  }

  // Compress / Decompress use integer multiply-shift arithmetic only (no
  // floating-point division of secret-derived values — the "KyberSlash" class).
  // compress(x, d) = floor((x * 2^d + 1664) / q) mod 2^d, with 330282857 = ceil(2^40 / q) (exact for every 0 <= x < q, d <= 10; products stay below 2^53).
  function mlkemCompress(f, d) {
    const r = new Int32Array(256);
    const mask = (1 << d) - 1;
    for (let i = 0; i < 256; i++) {
      const num = f[i] * (1 << d) + 1664;
      r[i] = Math.floor((num * 330282857) / 1099511627776) & mask;
    }
    return r;
  }

  function mlkemDecompress(f, d) {
    const r = new Int32Array(256);
    const half = 1 << (d - 1);
    for (let i = 0; i < 256; i++) {
      r[i] = (MLKEM_Q * f[i] + half) >> d;
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
   * ML-KEM.Encaps_internal (FIPS 203 Alg. 17) with caller-supplied message `m`.
   * Exposed for known-answer tests; production code uses `mlkem768Encaps`.
   */
  function mlkem768EncapsInternal(ek, m) {
    if (!(ek instanceof Uint8Array) || ek.length !== MLKEM_EK_BYTES) {
      throw new Error("Invalid ML-KEM-768 encapsulation key length");
    }
    // FIPS 203 §7.2 modulus check: ByteEncode12(ByteDecode12(ek)) must equal ek.
    for (let i = 0; i < MLKEM_K; i++) {
      const slice = ek.subarray(384 * i, 384 * (i + 1));
      const reEncoded = mlkemByteEncode(mlkemByteDecode(slice, 12), 12);
      if (!timingSafeEqualBytes(slice, reEncoded)) {
        throw new Error("Invalid ML-KEM-768 encapsulation key (failed FIPS 203 modulus check)");
      }
    }
    const hEk = sha3_256(ek);
    const kr = sha3_512(concatBytes(m, hEk));
    const sharedSecret = new Uint8Array(kr.subarray(0, 32));
    const c = mlkem768PkeEncrypt(ek, m, kr.subarray(32, 64));
    return { ct: c, ss: sharedSecret };
  }

  /** ML-KEM.Encaps — returns `{ ct (1088 B), ss (32 B) }`. */
  function mlkem768Encaps(ek) {
    const m = webCrypto.getRandomValues(new Uint8Array(32));
    try {
      return mlkem768EncapsInternal(ek, m);
    } finally {
      zeroize(m);
    }
  }

  /**
   * ML-KEM.Decaps with FIPS 203 §7.3 decapsulation-key check and
   * implicit rejection. The accept/reject selection is branch-free.
   */
  function mlkem768Decaps(dk, c) {
    if (
      !(dk instanceof Uint8Array) || dk.length !== MLKEM_DK_BYTES ||
      !(c instanceof Uint8Array) || c.length !== MLKEM_CT_BYTES
    ) {
      throw new Error("Invalid ML-KEM-768 key or ciphertext length");
    }
    const dkPke = dk.subarray(0, 1152);
    const ekPke = dk.subarray(1152, 2336);
    const h = dk.subarray(2336, 2368);
    const z = dk.subarray(2368, 2400);
    if (!timingSafeEqualBytes(sha3_256(ekPke), h)) {
      throw new Error("Invalid ML-KEM-768 decapsulation key (hash check failed)");
    }

    const mPrime = mlkem768PkeDecrypt(dkPke, c);
    const krPrime = sha3_512(concatBytes(mPrime, h));
    const kPrime = krPrime.subarray(0, 32);
    const kBar = shake256(concatBytes(z, c), 32);
    const cPrime = mlkem768PkeEncrypt(ekPke, mPrime, krPrime.subarray(32, 64));

    let diff = 0;
    for (let i = 0; i < c.length; i++) diff |= c[i] ^ cPrime[i];
    const mask = ((diff | -diff) >>> 31) - 1; // all-ones iff diff === 0
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = (kPrime[i] & mask) | (kBar[i] & ~mask);
    }
    zeroize(mPrime);
    return out;
  }

  // ── Padding (ISO/IEC 7816-4) ─────────────────────────────────────────────

  function padBytes(plainBytes, blockSize = 32) {
    const rem = (plainBytes.length + 1) % blockSize;
    const padLen = rem === 0 ? 1 : blockSize - rem + 1;
    const out = new Uint8Array(plainBytes.length + padLen);
    out.set(plainBytes, 0);
    out[plainBytes.length] = 0x80;
    return out;
  }

  /** Strict unpad: returns null if the padding is malformed. */
  function unpadBytes(paddedBytes) {
    for (let i = paddedBytes.length - 1; i >= 0; i--) {
      if (paddedBytes[i] === 0x80) return paddedBytes.subarray(0, i);
      if (paddedBytes[i] !== 0x00) return null;
    }
    return null;
  }

  // ── WebCrypto wrappers ───────────────────────────────────────────────────

  async function sha256(bytes) {
    return new Uint8Array(await webCrypto.subtle.digest("SHA-256", bytes));
  }

  async function hmacSha256(keyBytes, dataBytes) {
    const key = await webCrypto.subtle.importKey(
      "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    return new Uint8Array(await webCrypto.subtle.sign("HMAC", key, dataBytes));
  }

  async function hkdf(ikm, salt, info, length = 32) {
    const base = await webCrypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
    const bits = await webCrypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: typeof info === "string" ? enc.encode(info) : info },
      base,
      length * 8
    );
    return new Uint8Array(bits);
  }

  async function importAesKey(rawKeyBytes) {
    if (!rawKeyBytes || rawKeyBytes.length !== 32) {
      throw new Error("AES-256 key must be exactly 32 bytes");
    }
    return webCrypto.subtle.importKey("raw", rawKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  /** AES-256-GCM seal. Returns iv || ciphertext || tag. */
  async function aesGcmSeal(keyBytes, plaintext, aad) {
    const key = await importAesKey(keyBytes);
    const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ct = new Uint8Array(
      await webCrypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, plaintext)
    );
    return concatBytes(iv, ct);
  }

  async function aesGcmOpen(keyBytes, ivCt, aad) {
    if (ivCt.length < IV_BYTES + TAG_BYTES) throw new Error("Message too short");
    const key = await importAesKey(keyBytes);
    return new Uint8Array(
      await webCrypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivCt.subarray(0, IV_BYTES), additionalData: aad },
        key,
        ivCt.subarray(IV_BYTES)
      )
    );
  }

  // ── Ephemeral ECDH P-256 ─────────────────────────────────────────────────

  async function generateEcdhKeyPair() {
    const pair = await webCrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const pubRaw = new Uint8Array(await webCrypto.subtle.exportKey("raw", pair.publicKey));
    const privJwk = await webCrypto.subtle.exportKey("jwk", pair.privateKey);
    return { pubRaw, privJwk };
  }

  async function ecdhDerive(privJwk, peerPubRaw) {
    if (!(peerPubRaw instanceof Uint8Array) || peerPubRaw.length !== P256_PUB_BYTES || peerPubRaw[0] !== 0x04) {
      throw new Error("Invalid P-256 public key");
    }
    const priv = await webCrypto.subtle.importKey(
      "jwk",
      { kty: privJwk.kty, crv: privJwk.crv, x: privJwk.x, y: privJwk.y, d: privJwk.d, ext: true },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
    // importKey validates that the point is on the curve.
    const pub = await webCrypto.subtle.importKey(
      "raw", peerPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []
    );
    return new Uint8Array(await webCrypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
  }

  // ── Passphrase mode ──────────────────────────────────────────────────────
  // Only machine-generated 100-bit passphrases are accepted: a human-chosen
  // phrase cannot be made safe against offline guessing of captured ciphertext.

  function generatePassphrase() {
    const out = [];
    const random = webCrypto.getRandomValues(new Uint8Array(20));
    for (let i = 0; i < random.length; i++) out.push(PASSPHRASE_ALPHABET[random[i] & 31]);
    return [out.slice(0, 5), out.slice(5, 10), out.slice(10, 15), out.slice(15, 20)]
      .map((g) => g.join(""))
      .join("-");
  }

  /** Returns the canonical 20-character passphrase, or null if it is not a VeilX-generated one. */
  function normalizePassphrase(input) {
    if (typeof input !== "string") return null;
    const cleaned = input.normalize("NFKC").toUpperCase().replace(/[\s-]+/g, "");
    if (cleaned.length !== 20) return null;
    for (const ch of cleaned) if (!PASSPHRASE_ALPHABET.includes(ch)) return null;
    return cleaned;
  }

  async function deriveRootFromPassphrase(passphrase) {
    const canonical = normalizePassphrase(passphrase);
    if (!canonical) {
      throw new Error("Use a passphrase generated by VeilX (20 characters, e.g. ABCDE-FGHJK-LMNPQ-RSTUV).");
    }
    const baseKey = await webCrypto.subtle.importKey("raw", enc.encode(canonical), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await webCrypto.subtle.deriveBits(
      { name: "PBKDF2", salt: PASSPHRASE_SALT, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }

  // ── Vault encryption at rest ─────────────────────────────────────────────

  async function vaultKey(passphrase, salt) {
    const cleaned = passphrase.trim().normalize("NFKC");
    const baseKey = await webCrypto.subtle.importKey("raw", enc.encode(cleaned), { name: "PBKDF2" }, false, ["deriveBits"]);
    const keyBits = await webCrypto.subtle.deriveBits(
      { name: "PBKDF2", salt: concatBytes(enc.encode(VAULT_SALT_PREFIX), salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      256
    );
    return new Uint8Array(keyBits);
  }

  async function sealVaultData(passphrase, dataObj) {
    const salt = webCrypto.getRandomValues(new Uint8Array(16));
    const key = await vaultKey(passphrase, salt);
    const sealed = await aesGcmSeal(key, enc.encode(JSON.stringify(dataObj)), VAULT_AAD);
    zeroize(key);
    return {
      v: 1,
      saltB64: bytesToBase64(salt),
      ivB64: bytesToBase64(sealed.subarray(0, IV_BYTES)),
      ctB64: bytesToBase64(sealed.subarray(IV_BYTES)),
    };
  }

  async function unsealVaultData(passphrase, envelope) {
    if (!envelope || !envelope.saltB64 || !envelope.ivB64 || !envelope.ctB64) {
      throw new Error("Invalid vault envelope");
    }
    const key = await vaultKey(passphrase, base64ToBytes(envelope.saltB64));
    try {
      const plain = await aesGcmOpen(
        key,
        concatBytes(base64ToBytes(envelope.ivB64), base64ToBytes(envelope.ctB64)),
        VAULT_AAD
      );
      return JSON.parse(new TextDecoder().decode(plain));
    } finally {
      zeroize(key);
    }
  }


  // ── Sidecar Media Binary Encryption (VX1B) & Relay Request Binding ──────
  // NOTE ON RELAY AUTHENTICATION:
  //   A browser extension shipped to users cannot keep an embedded secret key confidential.
  //   By default (`relaySecret` empty), `signRelayUpload` computes a public request-binding
  //   MAC over `(timestamp, sha256Hex, powNonce)` so headers and body cannot be spliced in
  //   transit, while abuse prevention on the public prototype relay is enforced server-side
  //   via per-IP upload/download rate limits, per-IP byte quotas, and Proof-of-Work.
  //   Operators running a private relay can set a non-empty `RELAY_SECRET` on the Worker and
  //   in the VeilX popup to require keyed HMAC-SHA256 client authentication.
  const MEDIA_MAGIC = new Uint8Array([0x56, 0x58, 0x31, 0x42, 0x01]); // "VX1B\x01"
  const MAX_MEDIA_BYTES = 15 * 1024 * 1024; // 15 MB max media size
  const RELAY_POW_BITS = 14;
  const PUBLIC_RELAY_BINDING_TAG = "veilx-public-prototype-v1";

  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function hasLeadingZeroBits(bytes, bits) {
    const fullBytes = bits >>> 3;
    const remBits = bits & 7;
    for (let i = 0; i < fullBytes; i++) {
      if (bytes[i] !== 0) return false;
    }
    if (remBits > 0) {
      const mask = (0xff << (8 - remBits)) & 0xff;
      if ((bytes[fullBytes] & mask) !== 0) return false;
    }
    return true;
  }

  function computeRelayPow(timestampStr, sha256Hex, bits = RELAY_POW_BITS) {
    const prefixBytes = enc.encode(`VX1-POW:${timestampStr}:${String(sha256Hex).toLowerCase()}:`);
    const pLen = prefixBytes.length;
    if (pLen + 12 >= 136) {
      const prefix = `VX1-POW:${timestampStr}:${String(sha256Hex).toLowerCase()}:`;
      for (let nonce = 0; nonce < 0x7fffffff; nonce++) {
        if (hasLeadingZeroBits(sha3_256(enc.encode(prefix + nonce)), bits)) return String(nonce);
      }
      throw new Error("Could not compute relay Proof-of-Work.");
    }
    const block = new Uint8Array(136);
    block.set(prefixBytes, 0);
    const blockU32 = new Uint32Array(block.buffer);
    const sLo = new Uint32Array(25);
    const sHi = new Uint32Array(25);
    const headBytes = new Uint8Array(8);
    const headView = new DataView(headBytes.buffer);

    for (let nonce = 0; nonce < 0x7fffffff; nonce++) {
      const s = String(nonce);
      const sLen = s.length;
      for (let i = 0; i < sLen; i++) block[pLen + i] = s.charCodeAt(i);
      const end = pLen + sLen;
      for (let i = end; i < 136; i++) block[i] = 0;
      block[end] ^= 0x06;
      block[135] ^= 0x80;

      for (let j = 0; j < 17; j++) {
        sLo[j] = blockU32[j * 2];
        sHi[j] = blockU32[j * 2 + 1];
      }
      for (let j = 17; j < 25; j++) {
        sLo[j] = 0;
        sHi[j] = 0;
      }
      keccakF1600(sLo, sHi);
      headView.setUint32(0, sLo[0], true);
      headView.setUint32(4, sHi[0], true);
      if (hasLeadingZeroBits(headBytes, bits)) return s;
    }
    throw new Error("Could not compute relay Proof-of-Work.");
  }

  async function computeRelayPowAsync(timestampStr, sha256Hex, bits = RELAY_POW_BITS, onProgress) {
    const prefixBytes = enc.encode(`VX1-POW:${timestampStr}:${String(sha256Hex).toLowerCase()}:`);
    const pLen = prefixBytes.length;
    if (pLen + 12 >= 136) {
      return computeRelayPow(timestampStr, sha256Hex, bits);
    }
    const block = new Uint8Array(136);
    block.set(prefixBytes, 0);
    const blockU32 = new Uint32Array(block.buffer);
    const sLo = new Uint32Array(25);
    const sHi = new Uint32Array(25);
    const headBytes = new Uint8Array(8);
    const headView = new DataView(headBytes.buffer);

    for (let nonce = 0; nonce < 0x7fffffff; nonce++) {
      if ((nonce & 4095) === 4095) {
        if (typeof onProgress === "function") onProgress(nonce + 1);
        await new Promise((r) => setTimeout(r, 0));
      }
      const s = String(nonce);
      const sLen = s.length;
      for (let i = 0; i < sLen; i++) block[pLen + i] = s.charCodeAt(i);
      const end = pLen + sLen;
      for (let i = end; i < 136; i++) block[i] = 0;
      block[end] ^= 0x06;
      block[135] ^= 0x80;

      for (let j = 0; j < 17; j++) {
        sLo[j] = blockU32[j * 2];
        sHi[j] = blockU32[j * 2 + 1];
      }
      for (let j = 17; j < 25; j++) {
        sLo[j] = 0;
        sHi[j] = 0;
      }
      keccakF1600(sLo, sHi);
      headView.setUint32(0, sLo[0], true);
      headView.setUint32(4, sHi[0], true);
      if (hasLeadingZeroBits(headBytes, bits)) return s;
    }
    throw new Error("Could not compute relay Proof-of-Work.");
  }

  function verifyRelayPow(timestampStr, sha256Hex, nonceStr, bits = RELAY_POW_BITS) {
    if (typeof timestampStr !== "string" || typeof sha256Hex !== "string" || typeof nonceStr !== "string") {
      return false;
    }
    if (!/^[0-9]{1,12}$/.test(nonceStr) || !/^[0-9a-f]{64}$/i.test(sha256Hex)) return false;
    const digest = sha3_256(enc.encode(`VX1-POW:${timestampStr}:${sha256Hex.toLowerCase()}:${nonceStr}`));
    return hasLeadingZeroBits(digest, bits);
  }

  async function signRelayUpload({ timestamp, sha256Hex, powNonce, relaySecret }) {
    const keyMaterial = String(relaySecret || "").trim() || PUBLIC_RELAY_BINDING_TAG;
    const keyBytes = sha3_256(enc.encode("veilx-relay-key:" + keyMaterial));
    const msg = enc.encode(`VX1-AUTH:${timestamp}:${String(sha256Hex).toLowerCase()}:${powNonce}`);
    const mac = await hmacSha256(keyBytes, msg);
    zeroize(keyBytes);
    return bytesToBase64(mac);
  }

  async function verifyRelayUpload({
    timestamp,
    sha256Hex,
    powNonce,
    signatureB64,
    relaySecret,
    nowMs = Date.now(),
    maxSkewMs = 300000,
    powBits = RELAY_POW_BITS,
  }) {
    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || Math.abs(nowMs - ts) > maxSkewMs) return false;
    const cleanHex = String(sha256Hex || "").toLowerCase();
    if (!verifyRelayPow(String(timestamp), cleanHex, String(powNonce || ""), powBits)) return false;
    let sigBytes;
    try {
      sigBytes = base64ToBytes(String(signatureB64 || ""));
    } catch (_) {
      return false;
    }
    const expectedB64 = await signRelayUpload({
      timestamp: String(timestamp),
      sha256Hex: cleanHex,
      powNonce: String(powNonce),
      relaySecret,
    });
    return timingSafeEqualBytes(sigBytes, base64ToBytes(expectedB64));
  }

  /**
   * Encrypts raw media bytes (images, short videos, or voice notes) with a fresh
   * one-time 256-bit AES-GCM key and wraps the ciphertext in a `VX1B\x01` binary
   * envelope bound to the MIME type via AAD. Original file bytes are preserved
   * bit-for-bit without re-encoding.
   */
  async function sealMediaBinary(plainBytes, mimeType = "image/webp") {
    const raw = plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes || []);
    if (raw.length === 0) throw new Error("Cannot encrypt empty media payload.");
    if (raw.length > MAX_MEDIA_BYTES) {
      throw new Error(`Media file exceeds maximum allowed size (${Math.round(MAX_MEDIA_BYTES / (1024 * 1024))} MB).`);
    }
    const cleanMime = String(mimeType || "application/octet-stream").trim().toLowerCase();
    const mediaKey = webCrypto.getRandomValues(new Uint8Array(32));
    const aad = enc.encode("VX1B-v1:" + cleanMime);
    try {
      const ivCt = await aesGcmSeal(mediaKey, raw, aad);
      const envelopeBytes = concatBytes(MEDIA_MAGIC, ivCt);
      const digest = await sha256(envelopeBytes);
      return {
        envelopeBytes,
        keyB64: bytesToBase64(mediaKey),
        sha256B64: bytesToBase64(digest),
        sha256Hex: bytesToHex(digest),
        mimeType: cleanMime,
        size: raw.length,
      };
    } finally {
      zeroize(mediaKey);
    }
  }

  /**
   * Verifies the `VX1B\x01` magic header and SHA-256 integrity hash in constant time
   * before decrypting the media payload with the one-time 256-bit AES-GCM key.
   */
  async function openMediaBinary(envelopeBytes, keyB64, expectedSha256B64, mimeType = "image/webp") {
    const env = envelopeBytes instanceof Uint8Array ? envelopeBytes : new Uint8Array(envelopeBytes || []);
    if (env.length < MEDIA_MAGIC.length + IV_BYTES + TAG_BYTES + 1) {
      throw new Error("Truncated or malformed VX1B media blob.");
    }
    if (!timingSafeEqualBytes(env.subarray(0, MEDIA_MAGIC.length), MEDIA_MAGIC)) {
      throw new Error("Invalid media magic header (expected VX1B).");
    }
    const actualDigest = await sha256(env);
    const expectedDigest = base64ToBytes(String(expectedSha256B64 || ""));
    if (!timingSafeEqualBytes(actualDigest, expectedDigest)) {
      throw new Error("Media ciphertext integrity check failed (SHA-256 mismatch).");
    }
    const cleanMime = String(mimeType || "application/octet-stream").trim().toLowerCase();
    const keyBytes = base64ToBytes(String(keyB64 || ""));
    try {
      return await aesGcmOpen(keyBytes, env.subarray(MEDIA_MAGIC.length), enc.encode("VX1B-v1:" + cleanMime));
    } finally {
      zeroize(keyBytes);
    }
  }

  return {
    PBKDF2_ITERATIONS,
    MEDIA_MAGIC,
    MAX_MEDIA_BYTES,
    RELAY_POW_BITS,
    PUBLIC_RELAY_BINDING_TAG,
    IV_BYTES,
    TAG_BYTES,
    MLKEM_EK_BYTES,
    MLKEM_DK_BYTES,
    MLKEM_CT_BYTES,
    P256_PUB_BYTES,
    sha3_256,
    sha3_512,
    shake128,
    shake256,
    mlkem768KeyGen,
    mlkem768Encaps,
    mlkem768EncapsInternal,
    mlkem768Decaps,
    bytesToBase64,
    base64ToBytes,
    concatBytes,
    timingSafeEqualBytes,
    zeroize,
    padBytes,
    unpadBytes,
    sha256,
    hmacSha256,
    hkdf,
    importAesKey,
    aesGcmSeal,
    aesGcmOpen,
    generateEcdhKeyPair,
    ecdhDerive,
    generatePassphrase,
    normalizePassphrase,
    deriveRootFromPassphrase,
    sealVaultData,
    unsealVaultData,
    bytesToHex,
    computeRelayPow,
    computeRelayPowAsync,
    verifyRelayPow,
    signRelayUpload,
    verifyRelayUpload,
    sealMediaBinary,
    openMediaBinary,
    randomBytes: (n) => webCrypto.getRandomValues(new Uint8Array(n)),
  };
})();

if (typeof module !== "undefined") module.exports = VX.crypto;
