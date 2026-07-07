//! Report sharing: the JSON payload shape uploaded by `--share`, plus small
//! pure helpers shared between the CLI client (this module, always compiled)
//! and the `netblame-share` server (feature `share-server`, see
//! `src/bin/netblame_share.rs`).
//!
//! This module intentionally stays free of any networking/HTTP dependency so
//! it costs nothing in the default (client-only) build.

use crate::i18n::Lang;
use crate::report::Report;
use crate::verdict::RenderedVerdict;
use serde::Serialize;

/// Default share-server base URL, used when neither `--share-url` nor
/// `NETBLAME_SHARE_URL` is set. Not live yet as of v0.5 — upload failures
/// against it are expected and handled as a warning, not a hard error.
pub const DEFAULT_SHARE_URL: &str = "https://share.pathvector.dev";

/// Full JSON body posted to `POST /api/reports`. Same shape as `--json`
/// output, plus the two fields the share server needs to render the page:
/// the netblame version that produced it, and the language it should be
/// rendered in.
#[derive(Debug, Serialize)]
pub struct SharePayload<'a> {
    pub report: &'a Report,
    pub verdict: &'a RenderedVerdict,
    pub netblame_version: &'a str,
    pub created_lang: Lang,
}

/// Response returned by a successful `POST /api/reports`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ShareResponse {
    #[allow(dead_code)] // kept for API completeness / future use by the client
    pub id: String,
    pub url: String,
}

/// Resolves the base URL to upload to: `--share-url` flag, else
/// `NETBLAME_SHARE_URL` env var, else [`DEFAULT_SHARE_URL`]. Trailing
/// slashes are stripped so callers can join paths with a plain `/`.
pub fn resolve_base_url(flag: Option<&str>, env: Option<&str>) -> String {
    let raw = flag
        .filter(|s| !s.is_empty())
        .or(env.filter(|s| !s.is_empty()))
        .unwrap_or(DEFAULT_SHARE_URL);
    raw.trim_end_matches('/').to_string()
}

/// Server-side logic for `netblame-share` (id generation, retention pruning,
/// HTML rendering, rate limiting). Feature-gated so none of it — nor its
/// dependencies (axum, rand) — is compiled into the default `netblame`
/// binary.
#[cfg(feature = "share-server")]
pub mod server;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_prefers_flag() {
        assert_eq!(
            resolve_base_url(Some("https://flag.example/"), Some("https://env.example")),
            "https://flag.example"
        );
    }

    #[test]
    fn base_url_falls_back_to_env() {
        assert_eq!(
            resolve_base_url(None, Some("https://env.example/")),
            "https://env.example"
        );
    }

    #[test]
    fn base_url_falls_back_to_default() {
        assert_eq!(resolve_base_url(None, None), DEFAULT_SHARE_URL);
    }

    #[test]
    fn base_url_ignores_empty_strings() {
        assert_eq!(resolve_base_url(Some(""), Some("")), DEFAULT_SHARE_URL);
    }

    #[test]
    fn base_url_strips_trailing_slash() {
        assert_eq!(resolve_base_url(Some("http://x/"), None), "http://x");
    }
}
