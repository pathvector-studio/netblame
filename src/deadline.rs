//! `--max-time` の全体デッドライン管理。
//!
//! 個々のプローブは引き続き `--timeout` (プローブ単位) で動くが、この
//! モジュールはステージの境界で「もう時間がない」ことを協調的にチェック
//! するための軽量なヘルパーを提供する。スレッドの強制終了などはせず、
//! ステージ境界 + 各プローブの `tokio::time::timeout` の粒度で十分に
//! 全体時間を締め切りに近づける方針 (要件にある通り、約1プローブ分の
//! タイムアウト以内に収まれば良い簡易実装で構わない)。

use std::time::{Duration, Instant};

/// 全体デッドライン。`--max-time` 未指定なら `None` として扱う
/// (= 現行動作のまま、無制限)。
#[derive(Debug, Clone, Copy)]
pub struct Deadline {
    deadline: Instant,
}

impl Deadline {
    /// `--max-time <secs>` から構築する。
    pub fn from_secs(secs: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(secs.max(1)),
        }
    }

    /// ミリ秒単位で構築する。CLI からは秒単位 (`from_secs`) でしか指定でき
    /// ないが、テストで「ステージAは間に合うがステージBの境界チェックまでには
    /// 過ぎている」という短いデッドラインを再現するために使う。
    pub fn from_millis(ms: u64) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_millis(ms),
        }
    }

    /// 現在時刻がデッドラインを過ぎているか。
    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// デッドラインまでの残り時間 (過ぎていれば `Duration::ZERO`)。
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// 既に期限切れのデッドラインを作る。`diagnose` の最初のステージ境界
    /// チェックで確実に打ち切りパスへ入らせたいテストのためのヘルパー。
    pub fn already_expired() -> Self {
        Self {
            deadline: Instant::now(),
        }
    }
}

/// ステージを開始する前にチェックするヘルパー。
/// `Some(deadline)` かつ既に期限切れなら `true` (= このステージ以降は
/// スキップすべき)。`--max-time` 未指定 (`None`) なら常に `false`。
pub fn should_stop(deadline: Option<&Deadline>) -> bool {
    deadline.is_some_and(Deadline::expired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_deadline_not_expired() {
        let d = Deadline::from_secs(5);
        assert!(!d.expired());
        assert!(d.remaining() > Duration::from_secs(0));
    }

    #[test]
    fn zero_secs_clamped_to_one() {
        // from_secs(0) は誤用だが、即座に期限切れにはせず最低1秒は確保する
        let d = Deadline::from_secs(0);
        assert!(!d.expired());
    }

    #[test]
    fn should_stop_none_is_always_false() {
        assert!(!should_stop(None));
    }

    #[test]
    fn should_stop_true_after_expiry() {
        let d = Deadline::already_expired();
        std::thread::sleep(Duration::from_millis(5));
        assert!(should_stop(Some(&d)));
    }

    #[test]
    fn already_expired_is_expired() {
        let d = Deadline::already_expired();
        std::thread::sleep(Duration::from_millis(1));
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }
}
