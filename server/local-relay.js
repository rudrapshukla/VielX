/**
 * server/local-relay.js — Zero-dependency Node.js implementation of the VeilX
 * Encrypted Media Relay for local testing, hackathons, and self-hosting.
 *
 * Enforces the exact same security and abuse-control contract as `server/worker.js`:
 *   1. Per-IP sliding-window upload count, byte quota, and download rate limits (`429`)
 *   2. ±5-minute timestamp window + request-binding MAC (or operator `RELAY_SECRET` HMAC)
 *   3. 14-bit SHA3-256 Hashcash Proof-of-Work (`X-VeilX-PoW`)
 *   4. `VX1B\x01` binary magic header + SHA-256 integrity match (`X-VeilX-SHA256`) + 15 MB cap
 *   5. Unguessable 256-bit (64-hex) blob IDs with no directory listing + 5-download burn cap
 */

"use strict";

const http = require("node:http");
const VXCrypto = require("../src/crypto.js");

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_READS = 5;
const RATE_WINDOW_MS = 10 * 60 * 1000;

function createRelayHandler(options = {}) {
  const store = new Map(); // id -> { bytes: Uint8Array, expiresAt: number, remainingReads: number, sha256: string }
  const ipQuotas = new Map(); // ip -> { windowStart, uploads, bytes, downloads }
  const relaySecret = options.relaySecret || "";
  const maxReads = options.maxReads || DEFAULT_MAX_READS;
  const ttlMs = options.ttlMs || DEFAULT_TTL_MS;
  const powBits = options.powBits !== undefined ? options.powBits : VXCrypto.RELAY_POW_BITS;
  const maxUploadsPerIp = options.maxUploadsPerIp || 15;
  const maxBytesPerIp = options.maxBytesPerIp || 50 * 1024 * 1024;
  const maxDownloadsPerIp = options.maxDownloadsPerIp || 60;

  function checkIpQuota(ip, kind, byteCount = 0) {
    const now = Date.now();
    let rec = ipQuotas.get(ip);
    if (!rec || now - rec.windowStart >= RATE_WINDOW_MS) {
      rec = { windowStart: now, uploads: 0, bytes: 0, downloads: 0 };
      ipQuotas.set(ip, rec);
    }
    if (kind === "upload") {
      if (rec.uploads + 1 > maxUploadsPerIp || rec.bytes + byteCount > maxBytesPerIp) return false;
      rec.uploads += 1;
      rec.bytes += byteCount;
      return true;
    }
    if (kind === "download") {
      if (rec.downloads + 1 > maxDownloadsPerIp) return false;
      rec.downloads += 1;
      return true;
    }
    return true;
  }

  async function handleRequest({ method, path, origin, ip = "127.0.0.1", headers = {}, bodyBytes = new Uint8Array(0) }) {
    if (method === "OPTIONS") {
      return { status: 204, headers: {}, body: null };
    }

    const clientIp = String(headers["cf-connecting-ip"] || headers["x-forwarded-for"] || ip || "127.0.0.1");

    if ((method === "POST" || method === "PUT") && path === "/upload") {
      if (bodyBytes.length > VXCrypto.MAX_MEDIA_BYTES) {
        return { status: 413, json: { ok: false, error: "Payload exceeds 15 MB limit." } };
      }
      const timestamp = String(headers["x-veilx-timestamp"] || "");
      const claimedSha256 = String(headers["x-veilx-sha256"] || "").toLowerCase();
      const powNonce = String(headers["x-veilx-pow"] || "");
      const signatureB64 = String(headers["x-veilx-signature"] || "");

      const validAuth = await VXCrypto.verifyRelayUpload({
        timestamp,
        sha256Hex: claimedSha256,
        powNonce,
        signatureB64,
        relaySecret,
        powBits,
      });
      if (!validAuth) {
        return { status: 403, json: { ok: false, error: "Invalid relay signature, PoW, or timestamp." } };
      }

      if (
        bodyBytes.length < VXCrypto.MEDIA_MAGIC.length + VXCrypto.IV_BYTES + VXCrypto.TAG_BYTES + 1 ||
        !VXCrypto.timingSafeEqualBytes(bodyBytes.subarray(0, VXCrypto.MEDIA_MAGIC.length), VXCrypto.MEDIA_MAGIC)
      ) {
        return { status: 400, json: { ok: false, error: "Rejected: payload is not a VX1B encrypted envelope." } };
      }

      const actualHash = VXCrypto.bytesToHex(await VXCrypto.sha256(bodyBytes));
      if (actualHash !== claimedSha256) {
        return { status: 400, json: { ok: false, error: "Body SHA-256 mismatch." } };
      }

      if (!checkIpQuota(clientIp, "upload", bodyBytes.length)) {
        return {
          status: 429,
          json: { ok: false, error: "Per-IP upload rate limit or byte quota exceeded." },
        };
      }

      const id = VXCrypto.bytesToHex(VXCrypto.randomBytes(32));
      const expiresAt = Date.now() + ttlMs;
      store.set(id, {
        bytes: new Uint8Array(bodyBytes),
        expiresAt,
        remainingReads: maxReads,
        sha256: actualHash,
      });

      const baseOrigin = origin || "http://127.0.0.1:8787";
      return {
        status: 200,
        json: {
          ok: true,
          id,
          url: `${baseOrigin}/blob/${id}`,
          expiresAt,
          maxReads,
        },
      };
    }

    const match = /^\/blob\/([0-9a-f]{64})$/.exec(path);
    if (method === "GET" && match) {
      if (!checkIpQuota(clientIp, "download", 0)) {
        return { status: 429, json: { ok: false, error: "Per-IP download rate limit exceeded." } };
      }
      const id = match[1];
      const entry = store.get(id);
      if (!entry) {
        return { status: 404, json: { ok: false, error: "Encrypted blob not found or expired." } };
      }
      if (Date.now() > entry.expiresAt || entry.remainingReads <= 0) {
        store.delete(id);
        return { status: 404, json: { ok: false, error: "Encrypted blob expired." } };
      }
      entry.remainingReads -= 1;
      const outBytes = entry.bytes;
      if (entry.remainingReads <= 0) {
        store.delete(id);
      }
      return {
        status: 200,
        binary: outBytes,
      };
    }

    return { status: 403, json: { ok: false, error: "Forbidden." } };
  }

  return { store, ipQuotas, handleRequest };
}

function startLocalServer(port = Number(process.env.PORT || 8787), options = {}) {
  const relay = createRelayHandler(options);
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-VeilX-Timestamp, X-VeilX-SHA256, X-VeilX-PoW, X-VeilX-Signature",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total <= VXCrypto.MAX_MEDIA_BYTES + 1024) chunks.push(chunk);
    });
    req.on("end", async () => {
      try {
        const bodyBytes = new Uint8Array(Buffer.concat(chunks));
        const host = req.headers.host || `127.0.0.1:${port}`;
        const result = await relay.handleRequest({
          method: req.method,
          path: (req.url || "/").split("?")[0],
          origin: `http://${host}`,
          ip: req.socket && req.socket.remoteAddress,
          headers: req.headers,
          bodyBytes,
        });
        if (result.binary) {
          res.writeHead(result.status, {
            ...corsHeaders,
            "Content-Type": "application/octet-stream",
            "Content-Disposition": 'attachment; filename="veilx.bin"',
            "Content-Security-Policy": "default-src 'none'; sandbox",
          });
          res.end(Buffer.from(result.binary));
        } else if (result.json) {
          res.writeHead(result.status, {
            ...corsHeaders,
            "Content-Type": "application/json; charset=utf-8",
          });
          res.end(JSON.stringify(result.json));
        } else {
          res.writeHead(result.status, corsHeaders);
          res.end();
        }
      } catch (err) {
        res.writeHead(500, { ...corsHeaders, "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      resolve({
        server,
        relay,
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

if (require.main === module) {
  startLocalServer().then(({ url }) => {
    console.log(`[VeilX Relay] Zero-Knowledge Encrypted Media Relay listening on ${url}`);
  });
}

module.exports = { createRelayHandler, startLocalServer };
