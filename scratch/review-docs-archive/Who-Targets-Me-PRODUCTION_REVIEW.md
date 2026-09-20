# Production Readiness Review

Review date: 2026-09-20

Scope: this project folder only. The review focused on consequential production issues, excluding minor problems and style concerns. No implementation files were changed.

Six consequential issues should be fixed before production deployment.

## 1. [P1] Websites can change the extension's account and consent settings

The [content script](src/daemon/index.js) (lines 5–10) forwards arbitrary page messages, and the [background handler](src/shared/handlers/onMessageEventHandler.js) (line 14 onward) ignores sender identity. Scripts on any matched site—including localhost—can replace the token, delete local account state, or change consent.

An isolated probe reproduced token replacement and enabling previously disabled consent using untrusted sender URLs.

**Fix:** Authorize account-management messages against the exact trusted results origin in the background handler; restrict collector messages by sender platform and validate their payloads.

## 2. [P1] Registration credentials can leak to an unrelated website

[Registration feedback goes to whichever tab is currently active](src/shared/utils/postMessageToFirstActiveTab.js) (lines 3–4). If the user switches to another supported site while registration completes, its [content script](src/daemon/index.js) (lines 13–16) writes the token into that website's localStorage and broadcasts it. Scripts on that site can read the credential used for API authorization.

An isolated probe confirmed that the response is sent to an unrelated active tab.

**Fix:** Reply only to the originating, validated registration tab and document.

## 3. [P1] Account changes leave uploads authenticated as the previous account

The [API client](src/shared/api/app.js) (lines 7–15) captures its authorization token once, while `storeUserToken` changes storage without refreshing the client. A probe confirmed that switching stored credentials from account A to B leaves the Authorization header set to A. Uploads can therefore be misattributed—or fail when the client initially captured no token.

**Fix:** Resolve current credentials when sending requests, or explicitly rebuild the client on authentication changes.

## 4. [P1] Newly registered EU users bypass the collection exclusion

The [collection gate](src/shared/handlers/onMessageEventHandler.js) (lines 69–71) reads `userCountry`, but [registration](src/shared/handlers/handleUserRegistration.js) (lines 11–12) writes the country into `userData.country`. Only the installation/update handler populates `userCountry`, when a fresh installation usually has no account yet.

A probe reproduced German registration leaving the exclusion key absent, allowing consented uploads through. The cached country also survives account deletion.

**Fix:** Maintain one authoritative country value tied to the current account and define safe handling for unknown country.

## 5. [P1] Facebook collection can upload unrelated personal content

Once any sponsored object appears in a GraphQL response, the [collector](src/daemon/collector/platforms/facebook/handleApiResponse.js) (lines 28–34) forwards the entire response. It does not extract just the advertisement.

A synthetic response containing an advertisement alongside an ordinary personal post retained that personal post in the outgoing payload. Actual exposure depends on the response contents.

**Fix:** Extract individual advertisement objects and explicitly allowlist uploaded fields.

## 6. [P2] Firefox blocks the inline collector used by three platforms

The extension injects `daemon/inline-collector.js` into Facebook, Instagram, and YouTube, but the [Firefox manifest's web-accessible resource list](src/build/v2.manifest.template.json) (lines 22–27) omits it. Initial-page advertisements relying on this collector will be missed.

**Fix:** Declare the collector as an accessible resource and verify initial-page collection in Firefox.

## Deployment caveat

The [publish workflow](.github/workflows/main.yml) (line 23) builds with `OFFLINE=true`, embedding localhost API/results destinations. Those artifacts are unsuitable for production deployment. They may intentionally serve external tests; this repository alone does not establish the browser-store release process.

## Validation and limitations

Validation used source inspection and isolated Node probes with mocked browser/API interfaces. Dependencies were not installed, external services were not contacted, and live-browser tests were not run. All inspection stayed within this project folder.
