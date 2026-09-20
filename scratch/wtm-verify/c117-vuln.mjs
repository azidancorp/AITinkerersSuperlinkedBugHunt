// Candidate W5b (parked #117) VULN replay — handleUserCountry.js:5.
// Claim: for tokenless users readStorage("general_token") resolves null and
// `general_token.length` throws TypeError, so the EU rawlog-pause flow never
// engages at install/update.
// Oracle prints ONLY the claimed effect (CLAIM_EFFECT=...) so the vuln/control
// differential measures the claim, not fixture noise.
// Fact at HEAD: fix c09e0be ("conditionally reading general_token") IS an
// ancestor of HEAD 64e9989c65 — expected outcome here: CLAIM_EFFECT=none.
process.env.BROWSER = "chrome";
process.env.DATA_API_URL = "https://api.canary.example";

import { REPO, installChrome } from "./lib/env.mjs";

// Fresh install: no general_token, no userCountry in storage.
globalThis.chrome = installChrome({});

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
