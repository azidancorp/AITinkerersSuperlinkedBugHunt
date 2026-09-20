//! Shim standing in for the real `relay-client` crate so the real `origin.rs`
//! can be compiled byte-identical outside the workspace.
//!
//! The constant below is copied VERBATIM from
//! vibe-kanban/crates/relay-client/src/lib.rs:29 @ HEAD d5cbb5380f:
//!
//!   pub const RELAY_HEADER: &str = "x-vk-relayed";
//!
//! `origin.rs` imports nothing else from `relay_client`.

pub const RELAY_HEADER: &str = "x-vk-relayed";
