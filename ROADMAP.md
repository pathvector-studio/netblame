# netblame ロードマップ

## v0.2 (完了)

- ✅ 英語出力対応 — `--lang en|ja`、既定は `LC_ALL`/`LC_MESSAGES`/`LANG` から自動判定(日本語ロケール以外は英語)
- ✅ `--watch [秒]` モード — 診断を繰り返し、タイムスタンプ付きタイムラインで断続的な問題を捕捉。Ctrl-C でサマリー(実行回数・OK率・観測した問題と初回/最終発生時刻)

## v0.3

- [ ] traceroute / MTU プローブ — 「宅内 or ISP or 対岸」のホップ単位切り分けと PMTUD ブラックホール検出。CAP_NET_RAW が無い環境では graceful degrade
- [ ] QUIC/HTTP3 チェック — 「UDP 443 だけブロックされて HTTP/3 が壊れる」事故の検出

## v0.4

- [ ] レポート共有 — `--share` で `--json` レポートをアップロードして共有 URL を発行(share.pathvector.dev 構想)

## v1.0

- [ ] パッケージング — homebrew / cargo-binstall / AUR
- [ ] 判定閾値のフィールドデータに基づく調整(誤判定レポートの収集と反映)
