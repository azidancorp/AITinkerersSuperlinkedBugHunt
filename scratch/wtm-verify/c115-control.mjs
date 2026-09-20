// Candidate #115 CONTROL — same content-script listener, benign message with no
// registrationFeedback field: nothing should be stored or re-broadcast.
process.env.BROWSER = "chrome";
process.env.DATA_API_URL = "https://api.canary.example";
process.env.RESULTS_URL = "https://results.canary.example";

import { REPO, installChrome, installLocalStorage, sleep } from "./lib/env.mjs";

globalThis.chrome = installChrome({ general_token: "CANARY_TOKEN" });
installLocalStorage();

const postMessages = [];
globalThis.window = {
  location: { href: "https://example.com/" },
  addEventListener: () => {},
  postMessage: (...args) => postMessages.push(args),
};

const _contents = await import(`file://${REPO}/src/contents/index.js`);
await sleep(100);

const listener = chrome.runtime.onMessage._listeners[0];
if (typeof listener !== "function") {
  console.log("LISTENER_NOT_CAPTURED");
  process.exit(2);
}

listener({});

const stored = globalThis.localStorage.getItem("general_token");
const broadcast = postMessages.some((args) =>
  JSON.stringify(args[0]).includes("CANARY_TOKEN")
);

console.log("TOKEN_STORED=" + (stored === null ? "NONE" : stored));
console.log("POSTMESSAGE_BROADCAST=" + broadcast);
