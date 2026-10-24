/**
 * src/util.js — small helpers shared by the page code and the popup.
 *
 * Nothing in this file touches Instagram's page or the cryptography; it only
 * works with plain text and web addresses (URLs).
 */

globalThis.GPV = globalThis.GPV || {};

GPV.util = (() => {
  "use strict";

  // Instagram limits how long a single DM can be (~1000 characters).
  const MAX_MESSAGE_CHARS = 1000;
  // Safe UTF-8 byte budget per encrypted message chunk (leaves room for IV, GCM tag, padding, and Base64).
  const MAX_PLAINTEXT_BYTES = 680;

  /**
   * Find the chat ID inside a web address.
   *   "https://www.instagram.com/direct/t/1234567890/"  ->  "1234567890"
   * Returns null if the address is not an open chat.
   */
  function threadIdFromUrl(url) {
    try {
      const parsed = new URL(url);
      if (
        parsed.hostname !== "www.instagram.com" &&
        parsed.hostname !== "instagram.com"
      ) {
        return null;
      }
      const match = parsed.pathname.match(/^\/direct\/t\/([^/?#]+)/);
      return match ? match[1] : null;
    } catch (err) {
      return null;
    }
  }

  /** Last 6 characters of a chat ID, for showing in the popup and composer badge. */
  function shortId(threadId) {
    if (!threadId) return "";
    return threadId.length > 6 ? "…" + threadId.slice(-6) : threadId;
  }

  /** Return the UTF-8 byte length of a string. */
  function utf8ByteLength(text) {
    return new TextEncoder().encode(text || "").length;
  }

  /**
   * Split a long UTF-8 string into safe chunks so each chunk is at most `maxBytes`
   * UTF-8 bytes without ever splitting a multi-byte character or surrogate pair.
   */
  function splitIntoChunks(text, maxBytes = MAX_PLAINTEXT_BYTES) {
    const encoder = new TextEncoder();
    if (encoder.encode(text).length <= maxBytes) return [text];

    const chunks = [];
    let current = "";
    let currentBytes = 0;

    for (const codePoint of text) {
      const cpBytes = encoder.encode(codePoint).length;
      if (currentBytes + cpBytes > maxBytes && current.length > 0) {
        chunks.push(current);
        current = codePoint;
        currentBytes = cpBytes;
      } else {
        current += codePoint;
        currentBytes += cpBytes;
      }
    }
    if (current.length > 0) chunks.push(current);
    return chunks;
  }

  return {
    MAX_MESSAGE_CHARS,
    MAX_PLAINTEXT_BYTES,
    threadIdFromUrl,
    shortId,
    utf8ByteLength,
    splitIntoChunks,
  };
})();

if (typeof module !== "undefined") module.exports = GPV.util;
