// Candidate W5b (parked #117) CONTROL replay — benign twin: token present, the
// user-credentials service resolves the country via the synthetic feathers
// stub (no network). The claim predicts no bad effect in this state, so the
// expected output is identical to a fixed vuln run: CLAIM_EFFECT=none.
process.env.BROWSER = "chrome";
process.env.DATA_API_URL = "https://api.canary.example";

import { REPO, installChrome } from "./lib/env.mjs";

globalThis.chrome = installChrome({
  general_token: "CANARY_TOKEN",
  userCountry: "de",
});

const { handleUserCountry } = await import(
  `file://${REPO}/src/shared/handlers/handleUserCountry.js`
);

try {
  await handleUserCountry();
  console.log("CLAIM_EFFECT=none");
} catch (err) {
  console.log("CLAIM_EFFECT=" + err.constructor.name);
  process.exit(1);
}
