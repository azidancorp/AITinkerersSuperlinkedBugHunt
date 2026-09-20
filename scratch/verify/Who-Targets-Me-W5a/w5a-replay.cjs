// Canary-first differential replay for W5a (ledger #131):
// EU collection-exclusion bypass for newly registered users.
//
// Loads the ACTUAL HEAD source src/shared/handlers/onMessageEventHandler.js
// into a node:vm sandbox (imports stripped, browser/storage mocked) and drives
// the SEND_RAW_LOG gate with the storage state of a freshly registered German
// user: handleUserRegistration.js:11-12 writes country to userData.country,
// never to "userCountry" -- the key the gate reads at line 69.
//
//   vuln    : post-registration storage state (userCountry ABSENT, as on a
//             fresh install where handleUserCountry() returned "" pre-account)
//   control : identical state plus userCountry="de" (the key/value the gate
//             was designed to consult)
//
// Exit 1 + CANARY-COMPROMISED iff collection proceeds for an EU user.
// No network, synthetic canaries only. Usage: node w5a-replay.cjs vuln|control
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const REPO = path.resolve(__dirname, "../../../Who-Targets-Me");
const mode = process.argv[2];
if (!["vuln", "control"].includes(mode)) {
  console.error("usage: node w5a-replay.cjs vuln|control");
  process.exit(2);
}

function load(rel) {
  return fs.readFileSync(path.join(REPO, rel), "utf8")
    .replace(/^import\s[\s\S]*?from\s*"[^"]*";\s*\n/gm, "")
    .replace(/^import\s+"[^"]*";\s*\n/gm, "")
    .replace(/^export\s+const\s/gm, "const ")
    .replace(/^export\s*\{[^}]*\};?\s*$/gm, "");
}

// Storage state immediately after a fresh-install registration as a German
// user (country canary "de"). Registration stored userData.country="de".
const store = {
  general_token: "canary-token-de-user",
  userData: { isNotifiedRegister: true, country: "de" },
};
if (mode === "control") {
  store.userCountry = "de"; // the exclusion key the gate actually reads
}

const calls = { sendRawLog: [] };
const src = load("src/shared/handlers/onMessageEventHandler.js");
const ctx = vm.createContext({
  console,
  process: { env: { BROWSER: "chrome" } },
  sendRawLog: (p) => calls.sendRawLog.push(p),
  setToStorage: async (k, v) => { store[k] = v; },
  readStorage: async (k) => store[k],
  removeFromStorage: async (k) => { delete store[k]; },
  handleUserRegistration: async () => {},
  handleUserDeletion: async () => {},
  postMessageToFirstActiveTab: async () => {},
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
vm.runInContext(src + "\nthis.__handler = onMessageEventHandler;", ctx);

(async () => {
  await ctx.__handler({
    action: "SEND_RAW_LOG",
    payload: { type: "FACEBOOK", body: { advert: "canary-ad-payload" } },
  });
  await new Promise((r) => setTimeout(r, 50));
  console.log("mode:", mode);
  console.log("storage keys:", JSON.stringify(Object.keys(store)));
  console.log("sendRawLog invocations:", calls.sendRawLog.length);
  if (calls.sendRawLog.length > 0) {
    console.log("CANARY-COMPROMISED: EU-registered user (userData.country=de) " +
      "collected; gate read key 'userCountry' which registration never sets");
    process.exit(1);
  }
  console.log("CLEAN: collection gate excluded the EU user");
  process.exit(0);
})().catch((e) => { console.error("HARNESS-ERROR", e); process.exit(2); });
