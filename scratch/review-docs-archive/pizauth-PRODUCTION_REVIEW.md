# Production readiness review

Review date: 2026-09-20

Scope: this project folder only. Four consequential issues were identified for correction before production. The review did not modify application code.

## 1. High — Callback server permits resource-exhaustion attacks

Location: [src/server/http_server.rs](src/server/http_server.rs), `parse_get` (around line 280), and the HTTP/HTTPS connection handlers.

The 16 KB request limit is checked between unbounded `read_line()` calls. A client can send an arbitrarily long line without a newline, growing memory before validation. Connections also receive unlimited threads with no read or TLS-handshake deadline.

An unauthenticated client can exhaust memory, threads, or file descriptors. Default loopback binding limits exposure to local clients; externally configured listeners expose it remotely.

Recommended fix: enforce limits while reading, set connection deadlines, and bound concurrent handlers.

## 2. High — Short-lived tokens cause continuous refresh requests

Location: [src/server/refresher.rs](src/server/refresher.rs), `refresh_at` (around line 373).

Refresh time is calculated as `expiry - refresh_before_expiry`, whose default is 90 seconds. If the provider repeatedly issues 60-second tokens, every successful refresh immediately becomes overdue again. This continually calls the provider, potentially triggering rate limits and disrupting authentication.

Recommended fix: cap the refresh lead time relative to token lifetime and ensure successful refreshes cannot immediately repeat.

## 3. Medium — Reminder notifications can silently discard successful authentication

Locations: [src/server/notifier.rs](src/server/notifier.rs), notification state replacement (around line 89); [src/server/http_server.rs](src/server/http_server.rs), account-ID validation after token exchange (around line 201).

Updating `last_notification` replaces the token state and changes its `AccountId`. If a reminder fires while the callback exchanges an authorization code, the successful response is discarded because its saved ID is now invalid. The account remains pending even though its one-use code has been consumed. This happens even without a configured notification command.

Recommended fix: distinguish notification metadata changes from changes that invalidate an authentication attempt.

## 4. Medium — One stalled local client blocks every CLI request

Location: [src/server/mod.rs](src/server/mod.rs), request reading (around line 89) and the serial Unix-socket accept loop (around line 455).

Unix-socket requests run serially and wait indefinitely for EOF. A connected client that stalls before closing its write side prevents subsequent `show`, `dump`, `reload`, and `shutdown` requests from being processed. Applications depending on token retrieval then hang.

Recommended fix: add request deadlines, bounded framing, and bounded concurrent handling.

## Validation limitation

These are source-based findings. Execution was blocked because no Rust toolchain is configured. No toolchain was installed and no dependencies were downloaded. The findings have not been reproduced against a running application.
