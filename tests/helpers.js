"use strict";
// Two-party protocol test helper: each party has its own storage and its own module instances.
const path = require("node:path");
const SRC = path.join(__dirname, "..", "src") + path.sep;
const MODULES = ["crypto", "protocol", "util", "store", "session"];

function makeStorage() {
  const data = {};
  const clone = (x) => JSON.parse(JSON.stringify(x));
  return {
    data,
    api: {
      async get(k) {
        if (k === null) return clone(data);
        const out = {};
        for (const key of Array.isArray(k) ? k : [k]) if (key in data) out[key] = clone(data[key]);
        return out;
      },
      async set(v) { for (const [k, x] of Object.entries(v)) data[k] = clone(x); },
      async remove(k) { for (const key of Array.isArray(k) ? k : [k]) delete data[key]; },
    },
  };
}

let CURRENT = null;
globalThis.chrome = { storage: { local: {
  get: (k) => CURRENT.api.get(k), set: (v) => CURRENT.api.set(v), remove: (k) => CURRENT.api.remove(k),
} } };

function makeParty() {
  const storage = makeStorage();
  for (const m of MODULES) delete require.cache[require.resolve(SRC + m + ".js")];
  globalThis.VX = {};
  for (const m of MODULES) require(SRC + m + ".js");
  const vx = globalThis.VX;
  const on = (obj) => new Proxy(obj, {
    get(t, k) {
      const v = t[k];
      return typeof v === "function" ? (...a) => { CURRENT = storage; return v(...a); } : v;
    },
  });
  return { data: storage.data, session: on(vx.session), store: on(vx.store), protocol: vx.protocol, crypto: vx.crypto };
}

module.exports = { makeParty };
