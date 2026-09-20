//! V1 reflected-XSS replay harness (vibe-kanban ledger #105/#110).
//!
//! Code under test: `crates/server/src/routes/oauth.rs` @ HEAD d5cbb5380f,
//! `handoff_complete` error branch (:160-165) which formats the
//! attacker-controlled `error` query parameter into `simple_html_response`
//! (:435-461) — a `text/html` response with no escaping anywhere.
//!
//! Fidelity model (same as the V2/#106 harness):
//!   * `origin.rs` is included BYTE-IDENTICAL via #[path] (the real file).
//!   * Every span of oauth.rs below marked `// >>> oauth.rs:A-B` is a verbatim
//!     copy of those lines; `fidelity_check.py` asserts each span occurs
//!     verbatim in the pinned repo file.
//!   * The route wiring mirrors `crates/server/src/routes/mod.rs:70-86`:
//!     `/api` nest + `ValidateRequestHeaderLayer::custom(validate_origin)`.
//!   * Only the handler TAIL after the error/missing-code branches (handoff-
//!     state lookup + remote redeem, which needs `DeploymentImpl` and network)
//!     is replaced by a labelled stub. The branches under test run verbatim.

#[path = "/home/azidan/AQL/AI/AITinkerers/vibe-kanban/crates/server/src/middleware/origin.rs"]
mod origin;

use axum::{
    Router,
    extract::Query,
    http::{Response, StatusCode},
    routing::get,
};
use serde::Deserialize;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use uuid::Uuid;

// >>> oauth.rs:27
/// Base64-encoded 32x32 app icon (from `crates/tauri-app/icons/32x32.png`).
const APP_ICON_BASE64: &str = "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";
// <<<

// >>> oauth.rs:32-67
/// Shared CSS styles for standalone OAuth HTML pages (success & error).
/// Colors and typography match the app's design system (light mode defaults
/// from `packages/web-core/src/app/styles/new/index.css`).
const AUTH_PAGE_STYLES: &str = r#"<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f2f2f2;
    color: #333;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
    padding: 24px;
  }
  .logo { width: 40px; height: 40px; }
  .content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }
  .title {
    font-size: 13px;
    font-weight: 500;
    color: #0d0d0d;
  }
  .subtitle {
    font-size: 12px;
    color: #636363;
  }
</style>"#;
// <<<

// >>> oauth.rs:143-154
#[derive(Debug, Deserialize)]
struct HandoffCompleteQuery {
    handoff_id: Uuid,
    #[serde(default)]
    app_code: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// When set to "desktop", the callback page will not auto-close so the user
    /// can see the success message (e.g. when opened from the Tauri desktop app).
    #[serde(default)]
    source: Option<String>,
}
// <<<

// Harness handler: the two branches below are verbatim oauth.rs:160-172.
// The real handler's tail (take_oauth_handoff + remote handoff_redeem) needs
// DeploymentImpl and egress; it is NOT the code under test and is stubbed.
async fn handoff_complete(
    Query(query): Query<HandoffCompleteQuery>,
) -> Result<Response<String>, StatusCode> {
    // >>> oauth.rs:160-172
    if let Some(error) = query.error {
        return Ok(simple_html_response(
            StatusCode::BAD_REQUEST,
            format!("OAuth authorization failed: {error}"),
        ));
    }

    let Some(app_code) = query.app_code.clone() else {
        return Ok(simple_html_response(
            StatusCode::BAD_REQUEST,
            "Missing app_code in callback".to_string(),
        ));
    };
    // <<<

    // STUB (not repo code): real handler continues into handoff-state lookup.
    let _ = (app_code, query.handoff_id, query.source);
    Ok(simple_html_response(
        StatusCode::BAD_REQUEST,
        "STUB: handoff-state lookup not replayed".to_string(),
    ))
}

// >>> oauth.rs:435-461
fn simple_html_response(status: StatusCode, message: String) -> Response<String> {
    let body = format!(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OAuth Error</title>
    {AUTH_PAGE_STYLES}
  </head>
  <body>
    <div class="container">
      <img class="logo" src="data:image/png;base64,{APP_ICON_BASE64}" alt="Vibe Kanban">
      <div class="content">
        <p class="title">{message}</p>
        <p class="subtitle">Please close this tab and try again.</p>
      </div>
    </div>
  </body>
</html>"#
    );
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(body)
        .unwrap()
}
// <<<

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(41811);

    // Mirrors routes/mod.rs:70-86 — /api nest with the origin gate; the relay
    // signature layers are no-ops for non-relay requests
    // (relay_request_signature.rs:35-37, verified in the V2 worksheet).
    let api_routes = Router::new()
        .route("/auth/handoff/complete", get(handoff_complete))
        .layer(ValidateRequestHeaderLayer::custom(origin::validate_origin));

    let app = Router::new().nest("/api", api_routes);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind failed");
    println!("READY port={port}");
    axum::serve(listener, app).await.expect("server error");
}
