// Candidate #114 CONTROL — identical setup and identical HOSTILE sender, but
// the message is benign no-op traffic ({action:'UNKNOWN_ACTION'}) that the
// handler should process without touching the rawlog service.
process.env.BROWSER = "chrome";
process.env.DATA_API_URL = "https://api.canary.example";

import { REPO, installChrome, sleep } from "./lib/env.mjs";

globalThis.chrome = installChrome({
  general_token: "CANARY_TOKEN",
  wtm_user: { consent: { platforms: { twitter: true } } },
});

const { onMessageEventHandler } = await import(
  `file://${REPO}/src/shared/handlers/onMessageEventHandler.js`
);

const hostileSender = {
  id: "x",
  url: "https://evil.example/",
  origin: "https://evil.example",
};

await onMessageEventHandler(
  { action: "UNKNOWN_ACTION", payload: {} },
  hostileSender,
  () => {}
);

await sleep(150);

const rawlogCreates = (globalThis.__feathersServiceCalls || []).filter(
  (c) => c.service === "submit-rawlogs"
);

if (rawlogCreates.length > 0) {
  console.log("RAWLOG_SENT");
  console.log("CREATED=" + JSON.stringify(rawlogCreates[0].payload));
} else {
  console.log("NOT_SENT");
}
