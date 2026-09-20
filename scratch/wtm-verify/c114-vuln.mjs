// Candidate #114 VULN — onMessageEventHandler.js performs SEND_RAW_LOG with no
// sender/origin validation. A HOSTILE sender (https://evil.example) drives the
// real handler; the rawlog MUST NOT be stoppable by the sender identity.
process.env.BROWSER = "chrome";
process.env.DATA_API_URL = "https://api.canary.example";

import { REPO, installChrome, sleep } from "./lib/env.mjs";

// Logged-in, non-EU user who has consented for twitter — benign precondition.
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
  {
    action: "SEND_RAW_LOG",
    payload: { type: "TWITTER", body: { advert: "CANARY_RAWLOG" } },
  },
  hostileSender,
  () => {}
);

// sendRawLog is fire-and-forget inside the handler; give the microtask/timers
// a moment to reach feathers service.create.
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
