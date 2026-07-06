# netblame

[English](README.md) | 日本語

**それ、本当にネットワークのせい?**

> ⚠️ **プロトタイプ段階です。** 判定エンジンの閾値はヒューリスティックで、珍しいネットワーク環境では誤判定があり得ます。フィードバック歓迎。現在 Linux で動作確認済み(macOS はベストエフォート、Windows は未対応)。出力は日本語/英語対応(`--lang`、ロケール自動判定)。

「ネットが遅い」「サイトに繋がらない」— そのとき本当に悪いのは、ルータなのか、DNS なのか、途中の経路なのか、それともサーバなのか。`netblame` は URL / ホストを 1 つ渡すだけで段階診断を行い、**最も可能性の高い犯人を平易な日本語で名指し**するシングルバイナリの CLI です。

```
$ netblame https://example.com
...
【判定】 問題は見つかりませんでした。少なくとも今、この宛先への経路は健全です
```

## インストール

### バイナリ (推奨)

[Releases](https://github.com/pathvector-studio/netblame/releases) から Linux / macOS のバイナリをダウンロードして PATH に置いてください。

### ソースから

Rust ツールチェーン (1.85+) があればビルドできます。

```bash
git clone https://github.com/pathvector-studio/netblame.git
cd netblame
cargo build --release
# バイナリは target/release/netblame
```

## 使い方

```bash
netblame <target> [flags]
```

- `<target>`: URL (`https://example.com/path`, `http://host:8080`) または `host[:port]`
  - `https` スキームまたは素のホスト → ポート 443 + TLS
  - `http` スキーム → ポート 80、TLS なし
  - `host:port` (443/80 以外) → 素の TCP 診断 (TLS/HTTP はスキップ)

| フラグ | 意味 | 既定値 |
|---|---|---|
| `--json` | 機械可読なフルレポート (report + verdict) を JSON 出力 | - |
| `--timeout <secs>` | 各プローブのタイムアウト秒数 | 5 |
| `--samples <n>` | レイテンシ計測のサンプル数 | 5 |
| `--no-color` | 色つき出力を無効化 | - |
| `--lang <en\|ja>` | 出力言語 | ロケールから自動判定 |
| `--watch [<秒>]` | 診断を繰り返しタイムライン表示。Ctrl-C でサマリー | 30 |
| `--trace` | ホップ単位の経路トレースを常に実行 (下記参照) | 自動 |

**経路トレースの自動起動**: `--trace` を付けなくても、前段のステージで経路系の問題 (TCP タイムアウト / パケットロス > 0% / ジッタ大) が見つかったときだけ自動で実行されます。最悪 15〜30 秒ほどかかるため、健全時はスキップされます。トレースは tracepath 方式 (UDP + `IP_RECVERR`) で **root 権限不要**、ただし **Linux のみ対応**です (他 OS ではその旨を表示してスキップ)。

**QUIC/HTTP3 プローブ**: フラグ不要で、https ターゲットに対してのみ HTTP ステージの直後に自動実行されます。Linux / macOS 両対応です。

**終了コード**: `0` = 問題なし / `1` = 問題を検出 / `2` = 使い方・内部エラー

## 実行例 (実出力)

### 正常なサイト

```
$ netblame https://example.com
netblame: example.com (port 443) を診断します…

── 環境
  ✓ ネームサーバ: 127.0.0.53
  ✓ /etc/hosts: 上書きなし
  ✓ プロキシ環境変数: なし

── DNS
  ✓ システムリゾルバ: 4 件の回答 (374ms) [104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3]
  ✓ ローカル 127.0.0.53: 4 件の回答 (0ms) [104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3]
  ✓ 1.1.1.1 (Cloudflare): 4 件の回答 (27ms) [104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3]
  ✓ 8.8.8.8 (Google): 4 件の回答 (97ms) [104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3]

── TCP
  ✓ IPv4 104.20.23.154:443 接続成功 5/5 (min/avg/max 14ms/19ms/23ms)
  ✓ IPv6 2606:4700:10::6814:179a:443 接続成功 5/5 (min/avg/max 15ms/20ms/24ms)
  ✓ IPv4 172.66.147.243:443 接続成功 5/5 (min/avg/max 12ms/17ms/21ms)

── TLS
  ✓ ハンドシェイク成功: TLS 1.3 (30ms)
  ✓ 証明書の残り有効期間: 55 日
  ✓ 証明書チェーン検証: OK / ホスト名一致

── HTTP
  ✓ GET https://example.com/ → 200 (DNS 374ms / 接続 19ms / TLS 30ms / TTFB 95ms / 合計 95ms)

── 経路品質
  ✓ 5 回プローブ: ロス 0% / RTT min/avg/max 15ms/23ms/33ms / ジッタ 7ms

【判定】 問題は見つかりませんでした。少なくとも今、この宛先への経路は健全です
【根拠】
  ・名前解決: 正常
  ・TCP 接続: 正常 (17ms)
  ・TLS: 正常 (TLS 1.3, 証明書残り 55 日)
  ・HTTP: 200 (TTFB 95ms)
  ・経路品質: ロス 0% / ジッタ 7ms
【次の一手】 問題が断続的なら、症状が出ている最中にもう一度実行してください
```

### 存在しないドメイン → 「ネットワークのせいではない」

```
$ netblame https://definitely-not-a-real-domain-xyz123.com

── DNS
  ✗ システムリゾルバ: NXDOMAIN (名前が存在しない)
  ✗ ローカル 127.0.0.53: NXDOMAIN (名前が存在しない)
  ✗ 1.1.1.1 (Cloudflare): NXDOMAIN (名前が存在しない)
  ✗ 8.8.8.8 (Google): NXDOMAIN (名前が存在しない)

── TCP
  ✗ 接続先 IP がありません (名前解決に失敗)

【判定】 ドメイン「definitely-not-a-real-domain-xyz123.com」は存在しません。ネットワークのせいではありません
【根拠】
  ・問い合わせた全ての DNS サーバが NXDOMAIN (そんな名前は無い) と回答
  ・パブリック DNS (1.1.1.1 / 8.8.8.8) でも同じ回答
【次の一手】 ホスト名のタイプミスを確認してください。正しいはずなら、ドメインの有効期限切れの可能性があります
```

### 閉じたポート (フィルタ)

```
$ netblame example.com:81 --timeout 2

── TCP
  ✗ IPv4 104.20.23.154:81 タイムアウト (フィルタ/到達不能)
  ✗ IPv6 2606:4700:10::6814:179a:81 タイムアウト (フィルタ/到達不能)
  ✗ IPv4 172.66.147.243:81 タイムアウト (フィルタ/到達不能)

── 経路トレース
   1  192.168.40.1  2ms
   2  *  (応答なし)
   3  10.202.122.116  22ms
   4  10.84.8.19  14ms
   ...
  10  103.22.201.21  28ms
  11  104.20.23.154  14ms
  ✓ 宛先に到達 (11 ホップ)
  ✓ 経路 MTU: 1500

【判定】 ポート 81 への TCP 接続がタイムアウトします (フィルタ/到達不能)
【根拠】
  ・名前解決は成功しているが、TCP 接続が全ての IP でタイムアウト
  ・途中のファイアウォールで落とされているか、経路が死んでいる
  ・最後に応答したホップ: 104.20.23.154 (ホップ 11 / 推定経路長 ~11)
【次の一手】 別ネットワーク (スマホのテザリング等) から試して切り分けてください。そちらで繋がるなら今のネットワークのフィルタが原因です
```

TCP タイムアウト検出により経路トレースが自動起動しています。トレースが途中のホップで止まる場合は、止まった位置に応じて「宅内 (ホップ 1-2) / ISP 網内 (序盤) / 対岸 (奥)」の切り分けガイダンスが【次の一手】に追記されます。

### QUIC/HTTP3 (v0.4)

```
$ netblame https://cloudflare.com

── HTTP
  ✓ リダイレクト: 301 -> https://www.cloudflare.com/
  ✓ GET https://cloudflare.com/ → 200 (DNS 0ms / 接続 21ms / TLS 32ms / TTFB 293ms / 合計 482ms)

── QUIC/HTTP3
  ✓ QUIC ハンドシェイク成功: 22ms (h3)
  ✓ alt-svc で HTTP/3 が広告されています: h3=":443"; ma=86400
```

UDP 443 がファイアウォールで落とされている環境では、TCP/TLS/HTTP は正常なまま QUIC だけがタイムアウトし、以下のように判定されます:

```
── QUIC/HTTP3
  ✗ UDP 443 応答なし (タイムアウト)

【判定】 TCP は正常ですが、UDP 443 (QUIC/HTTP3) には全く到達できません
【根拠】
  ・TCP 443 は正常 (TLS ハンドシェイク・HTTP リクエストともに成功) — 問題は UDP 443 に限定されている
  ・QUIC ハンドシェイクの試行が全て無応答
  ・TCP 443 は正常だが UDP 443 の QUIC が全て無応答 — ファイアウォールが UDP 443 を落としている可能性が高い
【次の一手】 ブラウザは HTTP/2 にフォールバックするため気づきにくいが、初回接続の遅延や HTTP/3 前提のサービスで問題になります。FW ルールで UDP 443 を確認してください
```

この判定は意図的に最低優先度です。他に大きな問題があるときは QUIC の不調は【所見】に格下げされ、HTTP/3 が広告されていないサーバでの QUIC タイムアウトは想定内として主犯にはなりません。

### 期限切れ証明書

```
$ netblame https://expired.badssl.com --samples 2

── TLS
  ✗ 証明書検証失敗: invalid peer certificate: certificate expired: ...
  ⚠ 提示された発行者: C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Domain Validation Secure Server CA

【判定】 サーバの TLS 証明書が期限切れです。ネットワークのせいではありません
【根拠】
  ・証明書は 4101 日前に失効
  ・TCP 接続までは正常 = 経路は問題なし
【次の一手】 サーバ管理者に証明書の更新を依頼してください。自分のサイトなら証明書を更新してください
```

## アーキテクチャ

### 診断ステージ (src/probe/)

情報収集と判定を完全に分離しています。各ステージは `Report` (src/report.rs) に計測結果を積むだけで、「何が悪いか」は一切判断しません。

1. **環境** (`env.rs`) — `/etc/resolv.conf` (ネームサーバ・search ドメイン)、`/etc/hosts` の上書きエントリ、プロキシ環境変数 (`http_proxy` / `https_proxy` / `NO_PROXY` 等) を検出
2. **DNS** (`dns.rs`) — 4 系統で名前解決して比較: (a) システムリゾルバ (getaddrinfo)、(b) resolv.conf の各ネームサーバへの直接クエリ (hickory-resolver)、(c) 1.1.1.1、(d) 8.8.8.8。系統ごとに回答 IP・結果コード (OK/NXDOMAIN/SERVFAIL/タイムアウト)・レイテンシを記録
3. **TCP** (`tcp.rs`) — 解決済み IP 最大 3 つ (IPv4/IPv6 両方を含むよう選択) に N 回接続し、成功率と min/avg/max を計測。refused (ポート閉) / timeout (フィルタ) を区別
4. **TLS** (`tls.rs`) — rustls + webpki-roots で検証つきハンドシェイク。TLS バージョン・証明書の残り有効日数・ホスト名一致を記録。検証失敗時は**無検証 (読み取り専用・診断目的のみ)** で再接続して提示された証明書の発行者を取得し、Zscaler / FortiGate 等のミドルボックス痕跡があれば TLS 傍受の疑いを立てる
5. **HTTP** (`http.rs`) — reqwest (rustls バックエンド) で GET。ステータス・リダイレクトチェーン (最大 5)・TTFB・合計時間を計測し、DNS/接続/TLS の内訳は各ステージの実測値を転記。あわせて alt-svc 応答ヘッダを取得し、HTTP/3 (`h3`) が広告されているかを記録
6. **QUIC/HTTP3** (`quic.rs`) — HTTP ステージの後、**https ターゲットのみ**で実行。解決済み IP に対して ALPN `h3` で実際に QUIC ハンドシェイクを試行 (TLS ステージと同じ検証方針の rustls + webpki-roots) し、ハンドシェイク時間を計測。成功、タイムアウト (何も返ってこない = UDP 443 ブロックの兆候)、ハンドシェイクエラー (サーバは応答したがネゴシエーション失敗 = ネットワークの問題ではない)、ローカルエラーを区別
7. **経路品質** (`path.rs`) — 主要 IP へ TCP connect ping を N 回打ち、ロス率・平均 RTT・ジッタ (標準偏差) を算出
8. **経路トレース** (`trace.rs`, Linux のみ・root 不要) — tracepath 方式の traceroute。非特権 UDP ソケットに `IP_RECVERR` を設定し、`MSG_ERRQUEUE` 経由で ICMP time-exceeded / port-unreachable を受信してホップごとのルータアドレスと RTT を記録 (TTL 1〜30、各 2 プローブ・1 秒タイムアウト)。さらに `IP_PMTUDISC_PROBE` で DF ビット付きデータグラム (1500→1024 バイト) を送り、経路 MTU と「超過パケットが ICMP 通知なしで消えるか」(PMTUD ブラックホールの兆候) を観測

### 判定エンジン (src/verdict.rs)

`fn judge(report: &Report) -> Verdict` は **I/O を持たない純粋関数**で、証拠から犯人カテゴリを 1 つ選びます (ユニットテストで検証)。

犯人カテゴリ: `LocalDnsBroken` / `LocalDnsSlow` / `DnsAnswerMismatch` / `NameDoesNotExist` / `TcpBlocked` / `Ipv6Broken` / `TlsCertExpired` / `TlsCertInvalid` / `TlsIntercepted` / `ProxyInterference` / `UnstablePath` / `PmtuBlackhole` / `Udp443Blocked` / `ServerSlow` / `ServerDown` / `NoProblem`

判定の考え方 (優先度順):

- 全系統 NXDOMAIN → 名前が存在しない (ネットワークは無罪)
- パブリック DNS は引けるのにローカルが引けない → ローカル DNS 死亡
- ローカルとパブリックの回答が非交差 + 接続失敗 → 「ローカル DNS とパブリック DNS で回答が異なる」と中立に報告 (スプリットホライズン/フィルタ/書き換えの可能性)
- TCP 全滅: 全て refused → サーバ側のポート閉 / 全て timeout → フィルタ・到達不能
- IPv6 だけ全滅で IPv4 は正常 → IPv6 経路の故障 (実環境で頻出)
- 証明書期限切れ / ミドルボックス発行者 / チェーン不正 → TLS 系の犯人
- プロキシ設定あり + TCP 直結は成功なのに HTTP 失敗 → プロキシ干渉
- 接続は速い (<100ms) のに TTFB が遅い (>1000ms) → **サーバが遅い。ネットワークは正常**
- ロス ≥10% またはジッタ >50ms → 経路不安定
- TCP は通るのに、経路 MTU が 1500 未満 **かつ** 超過 DF プローブが ICMP 通知なしで消える → **`PmtuBlackhole`** — 小さい通信は通るのに大きい転送だけ止まる VPN/トンネルの典型事故。次の一手は トンネル MTU の確認 / MSS clamp
- TCP・TLS・HTTP が全て健全、alt-svc で HTTP/3 が広告されている **かつ** QUIC ハンドシェイクが全て無応答 → **`Udp443Blocked`** — ファイアウォールが UDP 443 を落としている可能性が高い。意図的に**最低優先度**の判定であり、他により大きな問題があればそちらが主犯になり QUIC の所見は【所見】に格下げされる。そもそも HTTP/3 が広告されていない場合の QUIC タイムアウトは想定内であり、主犯にはならず【所見】止まり
- 経路系の判定 (`TcpBlocked` / `ServerDown` / `UnstablePath`) でホップ情報がある場合、根拠に「最後に応答したホップ: <ip> (ホップ N / 推定経路長 ~M)」を追加し、止まった位置に応じて宅内 (ホップ 1-2) / ISP 網内 (序盤) / 対岸 (奥) の切り分けガイダンスを【次の一手】に追記
- ローカル DNS >200ms でパブリック <100ms → ローカル DNS が遅い

主犯にならなかった所見 (hosts 上書き、プロキシ検出、CDN による回答差、証明書の残日数僅少、非致命的な QUIC/HTTP3 異常) は【所見】として併記します。

## 開発

```bash
cargo test           # 判定エンジン + トレース解析 + パーサのユニットテスト (59 件)
cargo clippy         # 警告ゼロ
cargo build --release
```

## watch モード

断続的な問題こそ切り分けが難しい。`--watch` は診断を繰り返し、壊れた瞬間を記録します。

```
$ netblame --watch 30 https://example.com
watching every 30s — press Ctrl-C to stop and show a summary
10:12:42 ✓ OK (dns 1ms / tcp 16ms / ttfb 83ms / loss 0%)
...
── Watch summary
runs: 42 / ok: 40 (95%)
```

## 今後の拡張

[ROADMAP.md](ROADMAP.md) を参照。レポート共有を予定。

## ライセンス

MIT
