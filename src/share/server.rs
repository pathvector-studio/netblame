//! Pure logic backing the `netblame-share` binary. Split out from the axum
//! HTTP glue (which lives in `src/bin/netblame_share.rs`) so it is
//! unit-testable without a running server.

pub mod id;
pub mod ratelimit;
pub mod render;
pub mod retention;
