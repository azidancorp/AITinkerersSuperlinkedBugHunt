// Canary-first differential replay for W8 (ledger #132):
// API client captures the auth token once; account changes leave uploads
// authenticated as the previous account.
//
// Loads the ACTUAL HEAD source src/shared/api/app.js into a node:vm sandbox
// with @feathersjs/client and readStorage stubbed, lets its init IIFE capture
// general_token, then:
//
//   vuln    : switches the stored token A -> B (the storeUserToken path,
//             onMessageEventHandler.js:55-57, which performs NO extension
//             reload), then issues an API call and inspects the outgoing
//             Authorization header
//   control : identical, minus the account switch; API call must carry the
//             current stored token
//
// Exit 1 + CANARY-COMPROMISED iff the outgoing Authorization header does not
// match the currently stored token. Synthetic canaries only, no network.
// Usage: node w8-replay.cjs vuln|control
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const REPO = path.resolve(__dirname, "../../../Who-Targets-Me");
const mode = process.argv[2];
if (!["vuln", "control"].includes(mode)) {
  console.error("usage: node w8-replay.cjs vuln|control");
  process.exit(2);
}

function load(rel) {
  return fs.readFileSync(path.join(REPO, rel), "utf8")
    .replace(/^import\s[\s\S]*?from\s*"[^"]*";\s*\n/gm, "")
    .replace(/^import\s+"[^"]*";\s*\n/gm, "")
    .replace(/^export\s+const\s/gm, "const ")
    .replace(/^export\s*\{[^}]*\};?\s*$/gm, "");
}

const store = { general_token: "canary-token-account-A" };
const sent = []; // recorded outgoing requests

function fetchStub(url, opts) {
  sent.push({ url, authorization: opts && opts.headers && opts.headers.Authorization });
  return Promise.resolve({ json: async () => ({}), ok: true });
}

// Minimal @feathersjs/client stand-in preserving app.js's call shape:
// feathers() -> app.configure(restClient.fetch(fetch, {headers})) -> app.service(name).create(...)
function feathers() {
  return {
    configure(client) { this._client = client; return this; },
    service(name) {
      return {
        create: (body) => this._client.request("POST", name, body),
        get: (id) => this._client.request("GET", name + "/" + id),
      };
    },
  };
}
feathers.rest = (baseUrl) => ({
  fetch: (fetchFn, opts) => ({
    request: (method, path2, body) =>
      fetchFn(baseUrl + "/" + path2, { method, headers: opts.headers, body }),
  }),
});

const src = load("src/shared/api/app.js");
const ctx = vm.createContext({
  console,
  process: { env: { DATA_API_URL: "https://api.canary.invalid" } },
  feathers,
  fetch: fetchStub,
  readStorage: async (k) => store[k],
});
vm.runInContext(src + "\nthis.__app = app;", ctx);

(async () => {
  await new Promise((r) => setTimeout(r, 50)); // let the init IIFE capture the token
  if (mode === "vuln") {
    // storeUserToken: storage updated, no client rebuild, no reload
    store.general_token = "canary-token-account-B";
  }
  // real upload path: sendRawLog.js calls app.service("submit-rawlogs").create(...)
  await ctx.__app.service("submit-rawlogs").create({ advert: "canary-upload" });
  const current = store.general_token;
  const auth = sent.length ? sent[sent.length - 1].authorization : undefined;
  console.log("mode:", mode);
  console.log("current stored general_token:", current);
  console.log("outgoing Authorization header:", auth);
  if (auth !== current) {
    console.log("CANARY-COMPROMISED: upload authenticated as previous account " +
      "(stale token captured at module init)");
    process.exit(1);
  }
  console.log("CLEAN: upload carried the current account token");
  process.exit(0);
})().catch((e) => { console.error("HARNESS-ERROR", e); process.exit(2); });
