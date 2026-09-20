//! V2 origin-bypass replay harness (vibe-kanban ledger #106).
//!
//! Runs the REAL `crates/server/src/middleware/origin.rs` from the pinned
//! snapshot (HEAD d5cbb5380f), byte-identical, included via #[path] — no
//! copied logic. The layer wiring mirrors `crates/server/src/routes/mod.rs:70-78`:
//!
//!   let api_routes = Router::new()
//!       .merge(...)
//!       .layer(ValidateRequestHeaderLayer::custom(middleware::validate_origin))
//!
//! The probe handler stands in for every /api route (they are all merged
//! into that same layer and none takes any other auth extractor).

#[path = "/home/azidan/AQL/AI/AITinkerers/vibe-kanban/crates/server/src/middleware/origin.rs"]
mod origin;

use axum::{Router, routing::any};
use tower_http::validate_request::ValidateRequestHeaderLayer;

async fn probe() -> &'static str {
    // Marker proving the request REACHED the handler past the origin gate.
    "PROBE_OK"
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(41783);

    let app = Router::new()
        .route("/api/probe", any(probe))
        .layer(ValidateRequestHeaderLayer::custom(origin::validate_origin));

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind failed");
    println!("READY port={port}");
    axum::serve(listener, app).await.expect("server error");
}
