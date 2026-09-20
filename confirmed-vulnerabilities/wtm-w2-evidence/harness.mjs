// Independent verification harness for the Who-Targets-Me registrationFeedback claim.
// Executes the repo's ACTUAL source files at the pinned HEAD via node:vm
// (vm.SourceTextModule => real ESM semantics incl. live bindings/cycles).
// Only browser-platform primitives are mocked, encoding platform guarantees:
//   * chrome.storage.local          = extension-private storage
//   * content-script localStorage   = page-origin storage (same object page scripts see)
//   * window.postMessage(m, "*")    = delivered to EVERY window "message" listener
//   * chrome.tabs.query/sendMessage = background reaches the currently-active tab
//   * fetch                         = offline stub returning synthetic canary ONLY
// Third-party libs (feathers, cheerio, ...) are inert stubs except a minimal
// feathers REST client stand-in (documented; the extension code around it is real).
//
// usage: node harness.mjs <vuln|control>
//   vuln    : trigger = registration round-trip {registerWTMUser: true, ...}
//   control : trigger = unrelated real extension message {updateYGTab: true}

import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const REPO = "/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me";
const CANARY_TOKEN = "fresh-canary-token-7f3d9a";
const CANARY_API = "https://canary-data-api.invalid";
const MODE = process.argv[2];

if (!["vuln", "control"].includes(MODE)) {
  console.error("usage: node harness.mjs <vuln|control>");
  process.exit(2);
}

// --- guard: pinned HEAD -----------------------------------------------------
const head = execSync(`git -C ${REPO} rev-parse HEAD`).toString().trim();
if (!head.startsWith("64e9989c65")) {
  console.error(`ABORT: HEAD ${head} != pinned 64e9989c65`);
  process.exit(2);
}

// --- shared platform state --------------------------------------------------
const extStorage = {}; // chrome.storage.local (extension-private)
const pageLocalStorage = {}; // page-origin localStorage
const tabs = [{ id: 1, url: "https://www.facebook.com/", active: true }];
const bus = {
  bgListeners: [], // background runtime.onMessage
  tabListeners: { 1: [] }, // content-script runtime.onMessage, per tab
  sendToBackground(msg) {
    return Promise.all(bus.bgListeners.map((fn) => fn(msg)));
  },
  sendToTab(tabId, msg) {
    record.tabMessages.push({ tabId, msg });
    for (const fn of bus.tabListeners[tabId] || []) fn(msg);
  },
};
const record = { tabMessages: [], postMessages: [], fetchCalls: [], reloadCalled: false, pageObserverSawCanary: false };

// --- fetch: offline stub, canary only ----------------------------------------
const fetchStub = async (url, opts = {}) => {
  record.fetchCalls.push({ url, method: opts.method || "GET", headers: opts.headers || {}, body: opts.body || null });
  return {
    ok: true,
    json: async () => ({ token: CANARY_TOKEN, country: "canaryland" }),
    text: async () => "<html></html>",
  };
};

// --- third-party stubs (NOT extension code) ----------------------------------
function makeFeathers() {
  const feathers = function () {
    let restConfig = null;
    return {
      configure(cfg) {
        restConfig = cfg;
      },
      service(name) {
        const call = (method, suffix, body) =>
          restConfig
            .fetchFn(`${restConfig.base}/${name}${suffix}`, {
              method,
              headers: { "Content-Type": "application/json", ...restConfig.opts.headers },
              body: body ? JSON.stringify(body) : undefined,
            })
            .then((r) => r.json());
        return { create: (body) => call("POST", "", body), get: (id) => call("GET", `/${id}`) };
      },
    };
  };
  feathers.rest = (base) => ({ fetch: (fetchFn, opts) => ({ base, fetchFn, opts }) });
  return feathers;
}

function stubModule(context, names, impl) {
  const m = new vm.SyntheticModule(
    names,
    function () {
      for (const n of names) this.setExport(n, impl[n]);
    },
    { context }
  );
  return m;
}

// --- module loader: real repo source via vm.SourceTextModule -----------------
async function loadRepoModule(context, entryAbs, moduleCache) {
  const stubs = new Map();
  const feathers = makeFeathers();
  stubs.set("@feathersjs/client", stubModule(context, ["default"], { default: feathers }));
  stubs.set("cheerio", stubModule(context, ["load"], { load: () => ({}) }));
  stubs.set("jsonpath-plus", stubModule(context, ["JSONPath"], { JSONPath: () => [] }));
  stubs.set("lodash", stubModule(context, ["default"], { default: {} }));
  stubs.set("jquery", stubModule(context, ["default"], { default: () => ({}) }));

  async function linker(spec, referencingModule) {
    if (stubs.has(spec)) return stubs.get(spec);
    if (!spec.startsWith(".")) throw new Error(`unstubbed bare specifier: ${spec}`);
    const base = path.resolve(path.dirname(referencingModule.identifier), spec);
    for (const cand of [base, base + ".js", path.join(base, "index.js")]) {
      if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
        if (moduleCache.has(cand)) return moduleCache.get(cand);
        const code = fs.readFileSync(cand, "utf8"); // REAL source text, unmodified
        const mod = new vm.SourceTextModule(code, { context, identifier: cand });
        moduleCache.set(cand, mod);
        return mod;
      }
    }
    throw new Error(`cannot resolve ${spec} from ${referencingModule.identifier}`);
  }

  for (const [, s] of stubs) {
    await s.link(() => {
      throw new Error("stub has no imports");
    });
    await s.evaluate();
  }

  const code = fs.readFileSync(entryAbs, "utf8");
  const entry = new vm.SourceTextModule(code, { context, identifier: entryAbs });
  await entry.link(linker);
  await entry.evaluate();
  return entry;
}

// --- chrome facades -----------------------------------------------------------
function makeChromeFacade(role) {
  return {
    runtime: {
      onMessage: {
        addListener(fn) {
          (role === "background" ? bus.bgListeners : bus.tabListeners[1]).push(fn);
        },
      },
      sendMessage(msg) {
        return bus.sendToBackground(msg); // content script -> background
      },
      onInstalled: { addListener() {} },
      reload() {
        record.reloadCalled = true;
      },
      getManifest: () => ({ version: "2.12.1" }),
      getURL: (p) => "chrome-extension://wtm/" + p,
      lastError: null,
    },
    tabs: {
      query(q, cb) {
        cb(tabs.filter((t) => !q.active || t.active));
      },
      sendMessage(tabId, msg) {
        bus.sendToTab(tabId, msg);
      },
      onActivated: { addListener() {} },
      create() {},
      update() {},
    },
    storage: {
      local: {
        get: () => Promise.resolve({ ...extStorage }),
        set: (obj) => {
          Object.assign(extStorage, obj);
          return Promise.resolve();
        },
        remove(key, cb) {
          delete extStorage[key];
          if (cb) cb();
          return Promise.resolve();
        },
      },
    },
    action: { onClicked: { addListener() {} }, setIcon: () => Promise.resolve() },
    browserAction: { onClicked: { addListener() {} }, setIcon: () => Promise.resolve() },
  };
}

// --- contexts -----------------------------------------------------------------
const procEnv = {
  env: { BROWSER: "chrome", DATA_API_URL: CANARY_API, RESULTS_URL: "https://canary-results.invalid/" },
};
const baseGlobals = { console, URL, setTimeout, clearTimeout, setInterval, queueMicrotask, process: procEnv, fetch: fetchStub };

const bgContext = vm.createContext({ ...baseGlobals, chrome: makeChromeFacade("background") });

// content-script context: window + page-origin localStorage + a PAGE-SCRIPT observer
const pageListeners = [];
const windowMock = {
  location: { href: "https://www.facebook.com/" },
  addEventListener(type, fn) {
    if (type === "message") pageListeners.push(fn);
  },
  postMessage(msg, targetOrigin) {
    record.postMessages.push({ msg, targetOrigin });
    // platform guarantee: postMessage(m,"*") reaches every listener on window
    for (const fn of pageListeners) fn({ source: windowMock, data: msg });
  },
};
const documentMock = {
  createElement: () => ({ dataset: {}, set src(v) {}, get src() { return ""; } }),
  head: { querySelectorAll: () => [], appendChild() {}, removeChild() {} },
  documentElement: { querySelectorAll: () => [], appendChild() {}, removeChild() {} },
};
const csContext = vm.createContext({
  ...baseGlobals,
  chrome: makeChromeFacade("contentscript"),
  window: windowMock,
  localStorage: {
    setItem: (k, v) => {
      pageLocalStorage[k] = String(v);
    },
    getItem: (k) => pageLocalStorage[k] ?? null,
    removeItem: (k) => delete pageLocalStorage[k],
  },
  document: documentMock,
});

// --- load real extension code -------------------------------------------------
await loadRepoModule(bgContext, path.join(REPO, "src/daemon/background/worker.js"), new Map());
await loadRepoModule(csContext, path.join(REPO, "src/daemon/index.js"), new Map()); // SHIPPED content script

// page-script observer: any script in the page can do this
pageListeners.push((event) => {
  const s = JSON.stringify(event.data);
  if (s.includes(CANARY_TOKEN)) record.pageObserverSawCanary = true;
});

// --- trigger (the ONLY difference between vuln and control) -------------------
const trigger =
  MODE === "vuln"
    ? { registerWTMUser: true, political_affiliation: "canary-party", age: 42, gender: "x", postcode: "0", country: "canaryland" }
    : { updateYGTab: true };

await bus.sendToBackground(trigger);
await new Promise((r) => setTimeout(r, 50)); // flush microtasks across contexts

// --- results ------------------------------------------------------------------
const pageCopy = pageLocalStorage["general_token"] ?? null;
const broadcastLeak = record.postMessages.some(
  (p) => p.targetOrigin === "*" && JSON.stringify(p.msg).includes(CANARY_TOKEN)
);
const leaked = pageCopy !== null && pageCopy.includes(CANARY_TOKEN) && broadcastLeak && record.pageObserverSawCanary;

const report = {
  mode: MODE,
  trigger,
  extensionStorageToken: extStorage["general_token"] ?? null,
  pageOriginLocalStorage_general_token: pageCopy,
  tabMessagesSent: record.tabMessages.map((m) => ({ tabId: m.tabId, keys: Object.keys(m.msg) })),
  postMessageStarCount: record.postMessages.filter((p) => p.targetOrigin === "*").length,
  pageScriptObserverSawCanary: record.pageObserverSawCanary,
  runtimeReloadCalled: record.reloadCalled,
  fetchCalls: record.fetchCalls.map((c) => ({ url: c.url, method: c.method, authorization: c.headers.Authorization ?? null })),
  verdict:
    MODE === "vuln"
      ? leaked
        ? "VULNERABLE-REPRODUCED"
        : "NOT-REPRODUCED"
      : leaked
        ? "UNEXPECTED-LEAK"
        : "BENIGN",
};
console.log(JSON.stringify(report, null, 2));

process.exit(MODE === "vuln" ? (leaked ? 0 : 1) : leaked ? 1 : 0);
