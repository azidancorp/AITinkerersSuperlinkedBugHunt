// Shared browser-global stubs for the Who-Targets-Me harnesses.
// Everything synthetic — CANARY values only, no real credentials.

export const REPO = "/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me";

// Minimal chrome.* stand-in. storage.local is Map-backed; get() with no
// argument resolves the whole store (readStorage.js relies on that).
export function installChrome(storageSeed = {}) {
  const store = new Map(Object.entries(storageSeed));
  const chromeStub = {
    runtime: {
      lastError: null,
      getManifest: () => ({ version: "9.9.9-canary" }),
      getURL: (p) => `chrome-extension://canary/${p}`,
      reload: () => {},
      sendMessage: (_msg) => Promise.resolve(),
      onMessage: {
        _listeners: [],
        addListener(cb) {
          this._listeners.push(cb);
        },
      },
    },
    storage: {
      local: {
        get: (_keys) => Promise.resolve(Object.fromEntries(store)),
        set: (obj) => {
          for (const [k, v] of Object.entries(obj)) store.set(k, v);
          return Promise.resolve();
        },
        remove: (key, cb) => {
          store.delete(key);
          if (cb) cb();
          return Promise.resolve();
        },
      },
    },
    tabs: {
      query: (_q, cb) => cb && cb([]),
      create: () => {},
      update: () => {},
      sendMessage: () => Promise.resolve(),
    },
    action: { setIcon: () => Promise.resolve() },
    extension: { getManifest: () => ({ version: "9.9.9-canary" }) },
  };
  return chromeStub;
}

// Map-backed localStorage stand-in for the content-script harness (#115).
export function installLocalStorage() {
  const m = new Map();
  globalThis.localStorage = {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear(),
    _map: m,
  };
  return globalThis.localStorage;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
