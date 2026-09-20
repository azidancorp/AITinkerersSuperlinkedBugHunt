// Candidate #116 VULN — youtube/getAdvertContext.js embeds the full
// window.location.href (including search_query) in the rawlog context, unlike
// the facebook/instagram/twitter siblings which strip query params.
import { REPO } from "./lib/env.mjs";

globalThis.window = {
  location: {
    href: "https://www.youtube.com/results?search_query=CANARY_TERM",
  },
};

const { getAdvertContext } = await import(
  `file://${REPO}/src/daemon/collector/platforms/youtube/getAdvertContext.js`
);

const context = getAdvertContext({}); // inline-JS path (apiUrl = null)

console.log("PLATFORM=youtube");
console.log("URL_IN_CONTEXT=" + context.url);
console.log("QUERY_LEAKED=" + context.url.includes("CANARY_TERM"));
