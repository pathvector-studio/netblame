//! Retention pruning: decides which stored report files are older than the
//! configured retention window. Pure decision logic only — the actual
//! directory scan and file deletion happen in the binary, which just calls
//! `should_prune` per file.

use std::time::{Duration, SystemTime};

/// True if a file last modified at `modified` should be pruned, given the
/// current time `now` and a retention window of `retention_days`.
pub fn should_prune(modified: SystemTime, now: SystemTime, retention_days: u32) -> bool {
    let max_age = Duration::from_secs(u64::from(retention_days) * 24 * 60 * 60);
    match now.duration_since(modified) {
        // File is older than the retention window.
        Ok(age) => age > max_age,
        // `modified` is in the future (clock skew, or a file written after
        // `now` was captured) — never prune those.
        Err(_) => false,
    }
}

/// Filters a list of `(name, modified)` pairs down to the ones that should
/// be pruned. Kept as a small pure helper so the binary's directory-scan
/// loop stays a thin wrapper.
pub fn files_to_prune<'a>(
    entries: impl IntoIterator<Item = (&'a str, SystemTime)>,
    now: SystemTime,
    retention_days: u32,
) -> Vec<&'a str> {
    entries
        .into_iter()
        .filter(|(_, modified)| should_prune(*modified, now, retention_days))
        .map(|(name, _)| name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn days_ago(now: SystemTime, days: u64) -> SystemTime {
        now - Duration::from_secs(days * 24 * 60 * 60)
    }

    #[test]
    fn keeps_recent_file() {
        let now = SystemTime::now();
        let modified = days_ago(now, 1);
        assert!(!should_prune(modified, now, 30));
    }

    #[test]
    fn prunes_file_older_than_retention() {
        let now = SystemTime::now();
        let modified = days_ago(now, 31);
        assert!(should_prune(modified, now, 30));
    }

    #[test]
    fn boundary_exactly_at_retention_is_kept() {
        let now = SystemTime::now();
        let modified = days_ago(now, 30);
        // exactly at the boundary: age == max_age, not strictly greater
        assert!(!should_prune(modified, now, 30));
    }

    #[test]
    fn future_mtime_is_never_pruned() {
        let now = SystemTime::now();
        let modified = now + Duration::from_secs(3600);
        assert!(!should_prune(modified, now, 30));
    }

    #[test]
    fn files_to_prune_filters_correctly() {
        let now = SystemTime::now();
        let entries = vec![
            ("fresh", days_ago(now, 1)),
            ("stale", days_ago(now, 60)),
            ("boundary", days_ago(now, 30)),
        ];
        let pruned = files_to_prune(entries, now, 30);
        assert_eq!(pruned, vec!["stale"]);
    }

    #[test]
    fn zero_retention_days_prunes_anything_with_nonzero_age() {
        let now = SystemTime::now();
        let modified = days_ago(now, 1);
        assert!(should_prune(modified, now, 0));
    }
}
