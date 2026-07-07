//! netblame library: staged network diagnosis + verdict engine, shared
//! between the `netblame` CLI binary and the (feature-gated) `netblame-share`
//! self-hostable report server.

pub mod i18n;
pub mod probe;
pub mod report;
pub mod share;
pub mod verdict;

/// ターゲット文字列のパースエラー (文言は i18n::parse_error が担当)
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    UnsupportedScheme(String),
    EmptyHost,
    UnclosedIpv6,
    InvalidPort(String),
}
