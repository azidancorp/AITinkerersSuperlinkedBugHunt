// Candidate #116 CONTROL — sibling facebook getAdvertContext on an equivalent
// URL with a tracking-ish query param (fbclid): the past fix
// (removeQueryParamsFromUrl) must strip it.
import { REPO } from "./lib/env.mjs";

globalThis.window = {
  location: {
    href: "https://www.facebook.com/posts/1?fbclid=CANARY_TERM",
  },
};

const { getAdvertContext } = await import(
  `file://${REPO}/src/daemon/collector/platforms/facebook/getAdvertContext.js`
);

const context = getAdvertContext();

console.log("PLATFORM=facebook");
console.log("URL_IN_CONTEXT=" + context.url);
console.log("QUERY_LEAKED=" + context.url.includes("CANARY_TERM"));
