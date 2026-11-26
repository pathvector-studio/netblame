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

    /// ミリ秒単位で構築する。テストで 1 秒より短いデッドラインを作るために
    /// 置いている。CLI からは秒単位 (`from_secs`) でしか指定できない。
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

    // 以下は `from_millis` を使った判定の固定。実時間にほぼ依存しないよう、
    // 0 (= 構築直後から期限切れ) と十分大きい値 (= 期限内) の対比だけにする
    // (60_000ms のケースは 60 秒の余裕に頼る)。
    //
    // 注: `expired` の境界 (`>=`) はこれらのテストでは固定できていない。
    // `>` に変えても全テストが通ることを確認済み (通常は構築と判定の間に
    // 時間が経過するため、同一時刻を厳密に突く入力がない)。ただし時計の分解能
    // が粗い環境では `from_millis(0)` 直後の判定で同じ `Instant` が返りうる。
    // その場合 `>=` なら expired=true、`>` なら false になるので、
    // `from_millis_zero_is_expired` は `>` だと環境次第で落ちうる。

    #[test]
    fn from_millis_zero_is_expired() {
        let d = Deadline::from_millis(0);
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
        assert!(should_stop(Some(&d)));
    }

    #[test]
    fn from_millis_large_is_not_expired() {
        let d = Deadline::from_millis(60_000);
        assert!(!d.expired());
        assert!(d.remaining() > Duration::ZERO);
        assert!(!should_stop(Some(&d)));
    }
}
