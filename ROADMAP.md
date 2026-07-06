# netblame ロードマップ

## v0.2 (完了)

- ✅ 英語出力対応 — `--lang en|ja`、既定は `LC_ALL`/`LC_MESSAGES`/`LANG` から自動判定(日本語ロケール以外は英語)
- ✅ `--watch [秒]` モード — 診断を繰り返し、タイムスタンプ付きタイムラインで断続的な問題を捕捉。Ctrl-C でサマリー(実行回数・OK率・観測した問題と初回/最終発生時刻)

## v0.3 (完了)

- ✅ traceroute / MTU プローブ — `--trace` (経路系の問題検出時は自動起動)。tracepath 方式 (UDP + `IP_RECVERR`、root 不要、Linux のみ) でホップ単位に「宅内 or ISP or 対岸」を切り分け、DF プローブで PMTUD ブラックホール (`PmtuBlackhole`) を検出。非対応環境・ICMP フィルタ環境では graceful degrade

## v0.4

- ✅ QUIC/HTTP3 チェック — 「UDP 443 だけブロックされて HTTP/3 が壊れる」事故の検出。https ターゲットで HTTP ステージ後に実際の QUIC (ALPN h3) ハンドシェイクを試行し、alt-svc の h3 広告と突き合わせて `Udp443Blocked` を判定(TCP/TLS/HTTP が全て健全な場合のみ主犯にする低優先度の判定)
- [ ] レポート共有 — `--share` で `--json` レポートをアップロードして共有 URL を発行(share.pathvector.dev 構想)

## v1.0

- [ ] パッケージング — homebrew / cargo-binstall / AUR
- [ ] 判定閾値のフィールドデータに基づく調整(誤判定レポートの収集と反映)
