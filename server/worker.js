/**
 * server/worker.js — VeilX Zero-Knowledge Encrypted Media Relay (Cloudflare Worker).
 *
 * Deployed at: https://veilx-relay.therealrudrashukla.workers.dev
 *
 * SECURITY & ABUSE-CONTROL ARCHITECTURE:
 *   1. Server-Side Per-IP Rate Limiting & Byte Quotas (`checkIpQuota`):
 *      Enforces sliding-window limits per client IP (`CF-Connecting-IP`):
 *        - Max 15 uploads per 10-minute window
 *        - Max 50 MB uploaded per 10-minute window
 *        - Max 60 downloads per 10-minute window
 *      Returns `429 Too Many Requests` (`Retry-After: 60`) when exceeded.
 *   2. Client-Side 14-bit SHA3-256 Hashcash Proof-of-Work (`X-VeilX-PoW`) +
 *      ±5-minute timestamp window (`X-VeilX-Timestamp`) + request-binding MAC
 *      (or private operator HMAC when `env.RELAY_SECRET` is configured).
 *   3. Strict `VX1B\x01` Binary Magic-Header & SHA-256 Body Verification (`X-VeilX-SHA256`)
 *      plus a 15 MB per-blob ceiling.
 *   4. Unguessable 256-bit (64-hex) capability IDs with zero directory listing (`GET /` -> 403).
 *   5. Ephemeral Burn-After-Read & TTL (5 reads max, 24h TTL) enforced consistently across
 *      Cloudflare R2 (`env.VEILX_BUCKET`), Cloudflare Edge Cache (`caches.default`), AND
 *      isolate memory (`edgeMemoryStore`), always served with `Content-Type: application/octet-stream`
 *      and `X-Content-Type-Options: nosniff`.
 */

const MEDIA_MAGIC = new Uint8Array([0x56, 0x58, 0x31, 0x42, 0x01]); // "VX1B\x01"
const MAX_MEDIA_BYTES = 15 * 1024 * 1024; // 15 MB
const MAX_SKEW_MS = 5 * 60 * 1000;        // ±5 minutes
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_MAX_READS = 5;
const POW_BITS = 14;
const PUBLIC_RELAY_BINDING_TAG = "veilx-public-prototype-v1";

// Per-IP Sliding-Window Quotas (10-minute window)
const RATE_WINDOW_MS = 10 * 60 * 1000;
const MAX_UPLOADS_PER_IP = 15;
const MAX_BYTES_PER_IP = 50 * 1024 * 1024; // 50 MB / 10 min
const MAX_DOWNLOADS_PER_IP = 60;

const enc = new TextEncoder();
const edgeMemoryStore = new Map(); // id -> { bytes, expiresAt, remainingReads, sha256 }
const ipQuotaStore = new Map();    // ip -> { windowStart, uploads, bytes, downloads }

// ── Minimal FIPS 202 SHA3-256 for Edge PoW & Key Derivation ──────────────────

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
const ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

function sha3_256(inputBytes) {
  const rateBytes = 136;
  const sLo = new Uint32Array(25);
  const sHi = new Uint32Array(25);
  const block = new Uint8Array(200);
  const blockView = new DataView(block.buffer);
  let pos = 0;

  const absorb = () => {
    for (let j = 0; j < 17; j++) {
      sLo[j] ^= blockView.getUint32(j * 8, true);
      sHi[j] ^= blockView.getUint32(j * 8 + 4, true);
    }
    const bLo = new Uint32Array(5);
    const bHi = new Uint32Array(5);
    for (let round = 0; round < 24; round++) {
      for (let i = 0; i < 5; i++) {
        bLo[i] = sLo[i] ^ sLo[i + 5] ^ sLo[i + 10] ^ sLo[i + 15] ^ sLo[i + 20];
        bHi[i] = sHi[i] ^ sHi[i + 5] ^ sHi[i + 10] ^ sHi[i + 15] ^ sHi[i + 20];
      }
      for (let i = 0; i < 5; i++) {
        const i4 = (i + 4) % 5, i1 = (i + 1) % 5;
        const tLo = bLo[i4] ^ ((bLo[i1] << 1) | (bHi[i1] >>> 31));
        const tHi = bHi[i4] ^ ((bHi[i1] << 1) | (bLo[i1] >>> 31));
        for (let j = 0; j < 25; j += 5) { sLo[j + i] ^= tLo; sHi[j + i] ^= tHi; }
      }
      let tLo = sLo[1], tHi = sHi[1];
      for (let i = 0; i < 24; i++) {
        const j = PILN[i], n = ROTC[i];
        const nLo = n < 32 ? (tLo << n) | (tHi >>> (32 - n)) : (tHi << (n - 32)) | (tLo >>> (64 - n));
        const nHi = n < 32 ? (tHi << n) | (tLo >>> (32 - n)) : (tLo << (n - 32)) | (tHi >>> (64 - n));
        tLo = sLo[j]; tHi = sHi[j]; sLo[j] = nLo; sHi[j] = nHi;
      }
      for (let j = 0; j < 25; j += 5) {
        for (let i = 0; i < 5; i++) { bLo[i] = sLo[j + i]; bHi[i] = sHi[j + i]; }
        for (let i = 0; i < 5; i++) {
          const i1 = (i + 1) % 5, i2 = (i + 2) % 5;
          sLo[j + i] ^= ~bLo[i1] & bLo[i2];
          sHi[j + i] ^= ~bHi[i1] & bHi[i2];
        }
      }
      sLo[0] ^= RC_LO[round];
      sHi[0] ^= RC_HI[round];
    }
  };

  for (let i = 0; i < inputBytes.length; i++) {
    block[pos++] = inputBytes[i];
    if (pos === rateBytes) { absorb(); block.fill(0); pos = 0; }
  }
  block[pos] ^= 0x06;
  block[rateBytes - 1] ^= 0x80;
  absorb();

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let j = 0; j < 4; j++) {
    outView.setUint32(j * 8, sLo[j], true);
    outView.setUint32(j * 8 + 4, sHi[j], true);
  }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function hasLeadingZeroBits(bytes, bits) {
  const full = bits >>> 3;
  const rem = bits & 7;
  for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
  if (rem > 0 && (bytes[full] & ((0xff << (8 - rem)) & 0xff)) !== 0) return false;
  return true;
}

function getClientIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    "global-anon"
  );
}

function checkAndRecordIpQuota(ip, kind, byteCount = 0) {
  const now = Date.now();
  let rec = ipQuotaStore.get(ip);
  if (!rec || now - rec.windowStart >= RATE_WINDOW_MS) {
    rec = { windowStart: now, uploads: 0, bytes: 0, downloads: 0 };
    ipQuotaStore.set(ip, rec);
  }
  if (kind === "upload") {
    if (rec.uploads + 1 > MAX_UPLOADS_PER_IP || rec.bytes + byteCount > MAX_BYTES_PER_IP) {
      return false;
    }
    rec.uploads += 1;
    rec.bytes += byteCount;
    return true;
  }
  if (kind === "download") {
    if (rec.downloads + 1 > MAX_DOWNLOADS_PER_IP) {
      return false;
    }
    rec.downloads += 1;
    return true;
  }
  return true;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-VeilX-Timestamp, X-VeilX-SHA256, X-VeilX-PoW, X-VeilX-Signature",
  "Access-Control-Max-Age": "86400",
};

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...CORS_HEADERS,
      ...extraHeaders,
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
    },
  });
}

function binaryResponse(bytes, remainingReads) {
  return new Response(bytes, {
    status: 200,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="veilx.bin"',
      "X-Content-Type-Options": "nosniff",
      "X-VeilX-Remaining-Reads": String(remainingReads),
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Cache-Control": "no-store",
    },
  });
}

const workerHandler = {
  edgeMemoryStore,
  ipQuotaStore,
  async fetch(request, env = {}, ctx = { waitUntil() {} }) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const clientIp = getClientIp(request);
    const powBits = Number((env && env.POW_BITS) || POW_BITS);
    const maxReadsCfg = Number((env && env.MAX_READS) || DEFAULT_MAX_READS);

    // ── 1. Upload Encrypted VX1B Blob (`POST /upload` or `PUT /upload`) ──────
    if ((request.method === "POST" || request.method === "PUT") && url.pathname === "/upload") {
      const contentLen = Number(request.headers.get("content-length") || 0);
      if (contentLen > MAX_MEDIA_BYTES) {
        return jsonResponse({ ok: false, error: "Payload exceeds 15 MB limit." }, 413);
      }

      const timestamp = request.headers.get("x-veilx-timestamp") || "";
      const claimedSha256 = (request.headers.get("x-veilx-sha256") || "").toLowerCase();
      const powNonce = request.headers.get("x-veilx-pow") || "";
      const signatureB64 = request.headers.get("x-veilx-signature") || "";

      const tsNum = Number(timestamp);
      if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > MAX_SKEW_MS) {
        return jsonResponse({ ok: false, error: "Request timestamp expired or invalid." }, 403);
      }
      if (!/^[0-9a-f]{64}$/.test(claimedSha256) || !/^[0-9]{1,12}$/.test(powNonce)) {
        return jsonResponse({ ok: false, error: "Malformed integrity hash or PoW nonce." }, 400);
      }

      const powDigest = sha3_256(enc.encode(`VX1-POW:${timestamp}:${claimedSha256}:${powNonce}`));
      if (!hasLeadingZeroBits(powDigest, powBits)) {
        return jsonResponse({ ok: false, error: "Invalid Proof-of-Work." }, 403);
      }

      const secretStr = String((env && env.RELAY_SECRET) || PUBLIC_RELAY_BINDING_TAG).trim();
      const keyBytes = sha3_256(enc.encode("veilx-relay-key:" + secretStr));
      const cryptoKey = await crypto.subtle.importKey(
        "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const expectedMac = new Uint8Array(
        await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(`VX1-AUTH:${timestamp}:${claimedSha256}:${powNonce}`))
      );
      let providedMac;
      try {
        providedMac = base64ToBytes(signatureB64);
      } catch (_) {
        return jsonResponse({ ok: false, error: "Invalid signature encoding." }, 403);
      }
      if (!timingSafeEqual(expectedMac, providedMac)) {
        return jsonResponse({ ok: false, error: "Invalid request signature." }, 403);
      }

      const bodyBytes = new Uint8Array(await request.arrayBuffer());
      if (bodyBytes.length < 34 || bodyBytes.length > MAX_MEDIA_BYTES) {
        return jsonResponse({ ok: false, error: "Invalid payload size." }, 400);
      }
      if (!timingSafeEqual(bodyBytes.subarray(0, MEDIA_MAGIC.length), MEDIA_MAGIC)) {
        return jsonResponse({ ok: false, error: "Rejected: payload is not a VX1B encrypted envelope." }, 400);
      }

      const actualHash = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bodyBytes)));
      if (actualHash !== claimedSha256) {
        return jsonResponse({ ok: false, error: "Body SHA-256 mismatch." }, 400);
      }

      // Enforce per-IP upload count and byte quota
      if (!checkAndRecordIpQuota(clientIp, "upload", bodyBytes.length)) {
        return jsonResponse(
          { ok: false, error: "Per-IP upload rate limit or byte quota exceeded. Try again later." },
          429,
          { "Retry-After": "60" }
        );
      }

      const id = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const expiresAt = Date.now() + DEFAULT_TTL_MS;

      if (env && env.VEILX_BUCKET) {
        await env.VEILX_BUCKET.put(id, bodyBytes, {
          customMetadata: {
            expiresAt: String(expiresAt),
            remainingReads: String(maxReadsCfg),
            sha256: actualHash,
          },
        });
      } else {
        edgeMemoryStore.set(id, {
          bytes: bodyBytes,
          expiresAt,
          remainingReads: maxReadsCfg,
          sha256: actualHash,
        });
        try {
          if (typeof caches !== "undefined" && caches.default) {
            const cacheKey = new Request(`${url.origin}/__vx_cache/${id}`, { method: "GET" });
            const cacheResp = new Response(bodyBytes, {
              headers: {
                "Content-Type": "application/octet-stream",
                "Cache-Control": "public, max-age=86400",
                "X-VeilX-Expires": String(expiresAt),
                "X-VeilX-Remaining-Reads": String(maxReadsCfg),
              },
            });
            await caches.default.put(cacheKey, cacheResp);
          }
        } catch (_) {}
      }

      return jsonResponse({
        ok: true,
        id,
        url: `${url.origin}/blob/${id}`,
        expiresAt,
        maxReads: maxReadsCfg,
      });
    }

    // ── 2. Download Encrypted VX1B Blob (`GET /blob/:id`) ────────────────────
    const match = /^\/blob\/([0-9a-f]{64})$/.exec(url.pathname);
    if (request.method === "GET" && match) {
      if (!checkAndRecordIpQuota(clientIp, "download", 0)) {
        return jsonResponse(
          { ok: false, error: "Per-IP download rate limit exceeded. Try again later." },
          429,
          { "Retry-After": "60" }
        );
      }

      const id = match[1];
      const cacheKey = new Request(`${url.origin}/__vx_cache/${id}`, { method: "GET" });

      if (env && env.VEILX_BUCKET) {
        const obj = await env.VEILX_BUCKET.get(id);
        if (!obj) return jsonResponse({ ok: false, error: "Encrypted blob not found or expired." }, 404);
        const meta = obj.customMetadata || {};
        const expiresAt = Number(meta.expiresAt || 0);
        const remainingReads = Number(meta.remainingReads || 1);
        if ((expiresAt && Date.now() > expiresAt) || remainingReads <= 0) {
          ctx.waitUntil(env.VEILX_BUCKET.delete(id));
          return jsonResponse({ ok: false, error: "Encrypted blob expired." }, 404);
        }
        const bytes = new Uint8Array(await obj.arrayBuffer());
        const nextReads = remainingReads - 1;
        if (nextReads <= 0) {
          ctx.waitUntil(env.VEILX_BUCKET.delete(id));
        } else {
          ctx.waitUntil(
            env.VEILX_BUCKET.put(id, bytes, {
              customMetadata: { ...meta, remainingReads: String(nextReads) },
            })
          );
        }
        return binaryResponse(bytes, nextReads);
      }

      const mem = edgeMemoryStore.get(id);
      if (mem) {
        if (Date.now() > mem.expiresAt || mem.remainingReads <= 0) {
          edgeMemoryStore.delete(id);
          try {
            if (typeof caches !== "undefined" && caches.default) await caches.default.delete(cacheKey);
          } catch (_) {}
          return jsonResponse({ ok: false, error: "Encrypted blob expired." }, 404);
        }
        mem.remainingReads -= 1;
        const nextReads = mem.remainingReads;
        const outBytes = mem.bytes;
        if (nextReads <= 0) {
          edgeMemoryStore.delete(id);
          try {
            if (typeof caches !== "undefined" && caches.default) await caches.default.delete(cacheKey);
          } catch (_) {}
        } else {
          try {
            if (typeof caches !== "undefined" && caches.default) {
              await caches.default.put(
                cacheKey,
                new Response(outBytes, {
                  headers: {
                    "Content-Type": "application/octet-stream",
                    "Cache-Control": "public, max-age=86400",
                    "X-VeilX-Expires": String(mem.expiresAt),
                    "X-VeilX-Remaining-Reads": String(nextReads),
                  },
                })
              );
            }
          } catch (_) {}
        }
        return binaryResponse(outBytes, nextReads);
      }

      // Cloudflare Edge Cache fallback (when isolate memory is cold across edge PoPs):
      // Strictly enforces both TTL and the 5-download burn limit by decrementing X-VeilX-Remaining-Reads!
      try {
        if (typeof caches !== "undefined" && caches.default) {
          const cached = await caches.default.match(cacheKey);
          if (cached) {
            const expiresAt = Number(cached.headers.get("x-veilx-expires") || 0);
            const remainingReads = Number(cached.headers.get("x-veilx-remaining-reads") || 0);
            if ((expiresAt && Date.now() > expiresAt) || remainingReads <= 0) {
              await caches.default.delete(cacheKey);
              return jsonResponse({ ok: false, error: "Encrypted blob expired." }, 404);
            }
            const bytes = new Uint8Array(await cached.arrayBuffer());
            const nextReads = remainingReads - 1;
            if (nextReads <= 0) {
              await caches.default.delete(cacheKey);
            } else {
              await caches.default.put(
                cacheKey,
                new Response(bytes, {
                  headers: {
                    "Content-Type": "application/octet-stream",
                    "Cache-Control": "public, max-age=86400",
                    "X-VeilX-Expires": String(expiresAt),
                    "X-VeilX-Remaining-Reads": String(nextReads),
                  },
                })
              );
            }
            return binaryResponse(bytes, nextReads);
          }
        }
      } catch (_) {}

      return jsonResponse({ ok: false, error: "Encrypted blob not found or expired." }, 404);
    }

    return jsonResponse({ ok: false, error: "Forbidden." }, 403);
  },
};

export default workerHandler;
