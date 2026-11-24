# CI で netblame を使う

[English](ci.md) | 日本語

netblame は **終了コード** と、`--json` 指定時の機械可読レポートで結果を返す普通の CLI です。CI に必要なのはこれだけで、`$?` を見られる CI ならどこでも使えます。専用の GitHub Action、閾値指定オプション、JUnit 出力はありません。以下の例は終了コードと `jq` だけで組んでいます。

> ⚠️ **プロトタイプ段階です。** 判定の閾値はヒューリスティックなので、失敗が誤検知の可能性もあります。CI ではマージを止める厳格なゲートではなく、スモークチェックとして、あるいは **何かが失敗した後の証拠採取** として使うのがおすすめです。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 問題なし (判定が `no_problem`)。補足 (secondary) の指摘があるだけなら `0` のままです。 |
| `1` | 犯人を特定。`name_does_not_exist` (NXDOMAIN) や `server_down` も含み、`no_problem` 以外の判定はすべて `1` です。 |
| `2` | 使い方・内部エラー (ターゲットが解釈できない、`--json` と `--watch` の併用、JSON 化の失敗など)。 |
| `3` | **犯人を特定する前に** 打ち切られた (`--max-time` の期限切れ、または Ctrl-C / SIGINT)。`--max-time` の期限時点で犯人が特定済みなら終了コードは `1` です。Ctrl-C は途中結果を捨てて `3` になりますが、診断の実行中に限ります (下記「その他の終了のしかた」参照)。また `--json` 指定時に JSON 化に失敗すると `2` です。`--watch` は例外です (下記参照)。 |

`--share` は終了コードを変えません。アップロードに失敗しても stderr に警告が出るだけです。

CI で `--watch` は使わないでください。Ctrl-C まで診断を繰り返し続け、`--json` とも併用できません (終了コード `2`)。`--max-time` は watch 内の各回に適用されるだけで、ループ自体は止まりません。`--watch` では終了コードが異なります。終了するのは Ctrl-C のときだけで、期間中に犯人を特定した回が 1 度でもあれば `1`、なければ `0` で、`3` にはなりません。Ctrl-C で中断された回は破棄されて集計に含まれず、`--max-time` で打ち切られて犯人が見つからなかった回は問題なしとして数えられます。

### その他の終了のしかた

- Ctrl-C (SIGINT) 以外のシグナル (SIGTERM など) を受けると、プロセスはそのシグナルで終了し、その終了ステータスは上記のどの終了コードでもありません (シェルでは 143 など)。
- 診断の開始前に届いた Ctrl-C (SIGINT) は、netblame がまだ処理していないため、そのシグナルでプロセスが終了し (シェルでは `130`)、終了コード `3` にはなりません (`--watch` では `0` や `1` にもなりません)。この区間はプロセス起動 (引数の解析中) から診断が始まるまで続き、`diagnosing ...` 行 (`--watch` では `watching every ...` 行) を出力した直後も含みます (`--json` では `diagnosing ...` 行は出ませんが、区間は同じです)。
- 診断が終わった後に届いた Ctrl-C (SIGINT) は無視されます。netblame が一度 Ctrl-C の待ち受けを始めると OS 既定の動作 (終了) は元に戻らず、待ち受ける側ももういないためです。プロセスは止まらず、結果の出力後 (`--share` ではアップロードの終了後。アップロードは Ctrl-C で中断できません) に、診断結果で既に決まっている終了コード (`0`/`1`/`2`。`--max-time` の期限切れで犯人が未特定なら `3`) で終了します。この Ctrl-C によって `3` になることはありません。1 回目の Ctrl-C による打ち切りレポートの作成・出力中に届いた 2 回目の Ctrl-C も同様に無視され、終了コードは `3` のままです。`--watch` でも、各回の結果の出力中 (出力を終えて次の待機に入るまで) や最後のサマリの出力中に届いた Ctrl-C は同様に無視されます。回と回の待機中の Ctrl-C は通常どおり有効で、ループを止めます。
- main タスク (`main` を実行しているタスク) 上のパニックでは、プロセスは `101` で終了し、これは上記のどの終了コードでもありません。netblame 自身の DNS・経路追跡プローブが使うブロッキングタスク内のパニックは JoinError として捕捉され、診断は続行されます。依存ライブラリ (hickory-resolver・reqwest・quinn など) が内部で起動するタスクで起きたパニックの扱いはライブラリの実装しだいで、握りつぶされて続行することも、呼び出し側に伝わって異常終了 (`101`) することもあります。いずれの場合も、Rust 既定のパニックフックによりパニックメッセージは stderr に出力されます。

## CI で設定しておきたいフラグ

- `--max-time <秒>`: 診断全体の期限ですが、チェックされるのは **ステージの合間だけ** で、実行中のステージを途中で止めることはありません。期限を過ぎると、まだ始まっていないステージはスキップされ、部分レポートが出力されます。その時点で犯人が見つかっていなければ終了コードは `3` です。実行中のステージは必ず最後まで走るため、`--max-time` を最大でそのステージの所要時間ぶん超えることがあります。ネットワーク系の多くのステージは `--timeout <秒>` (既定 5、各プローブ単位) で制限されますが、trace ステージは `--timeout` を受け取らず、内部の固定上限 (約 75 秒) で打ち切られます。厳密な上限としてではなく `--timeout` と併用し、強い上限が必要なら CI 側のジョブのタイムアウトを使ってください。
- `--json`: JSON を 1 つ stdout に出力します。このモードでは他のものは stdout に出ないので `jq` にパイプできます (ただし `--share` を付けると JSON の後に共有 URL が stdout に出るので、`| jq` とは併用しないでください)。警告 (`--share` のアップロード失敗など) は stderr に出ます。
- `--lang en`: 出力言語を固定します。指定しないと `LC_ALL`、`LC_MESSAGES`、`LANG` から判定されます。
- `--no-color`: 色を無効にします。stdout が端末でない場合も自動的に無効になるので、多くの CI ログでは付けなくても色は出ません。
- `--trace`: ホップ単位の経路トレースを常に実行します (Linux のみ)。付けない場合は、前段で経路の問題が見つかったときだけ実行されます。

## JSON のフィールド

トップレベルのキーは `report` と `verdict` の 2 つです。

| パス | 値 |
|---|---|
| `.verdict.culprit_code` | ロケール非依存の snake_case コード。例: `"no_problem"`、`"local_dns_broken"`、`"server_down"`。**スクリプトではこれを使ってください。** 取りうる値は下の表にすべて載せています。 |
| `.verdict.culprit` | 同じカテゴリを variant 名で表したもの。例: `"NoProblem"`。 |
| `.verdict.headline`、`.evidence`、`.next_step`、`.secondary` | 人間向けの文章 (`--lang` の言語)。`evidence` と `secondary` は文字列の配列です。 |
| `.report.completeness.complete` | 打ち切られた場合は `false`。 |
| `.report.completeness.truncated_reason` | `null`、`"max_time_exceeded"`、`"interrupted"` のいずれか。 |
| `.report.completeness.ran_stages`、`.skipped_stages` | ステージ名 (`env`、`dns`、`tcp`、`tls`、`http`、`quic`、`path`、`trace`) の配列。 |
| `.report.stage_durations` | `{"stage": "...", "ms": 12.3}` の配列 (実行順)。 |

```bash
netblame --json --lang en --max-time 30 https://example.com > report.json || true   # 終了コード 1/3 は結果であり異常ではない (`set -e` 下で必要)。終了コード 2 (使い方・内部エラー) も握りつぶす点に注意
jq -r '.verdict.culprit_code' report.json
jq -r '.report.stage_durations[] | "\(.stage)\t\(.ms)"' report.json
jq -e '.report.completeness.complete' report.json   # 打ち切り検出用: 打ち切りなら終了コード 1 (`set -e` 下ではここでスクリプトが止まる)
```

### `culprit_code` の値

`.verdict.culprit_code` が取りうる全ての値です。1 回の実行で報告されるのは 1 つだけです。

| `culprit_code` | 意味 |
|---|---|
| `local_dns_broken` | ローカル系リゾルバに成功応答が 1 つも無い (SERVFAIL や NXDOMAIN も失敗として数える) のに、パブリック DNS は成功している。 |
| `local_dns_slow` | ローカル DNS が遅い (パブリック DNS は速い)。 |
| `dns_answer_mismatch` | ローカルとパブリックの IP 集合に重なりが無く、かつ全 TCP 接続が失敗、または TLS が失敗している (証明書検証の失敗を含む)。 |
| `name_does_not_exist` | 名前が存在しない (回答した全ソースが NXDOMAIN)。ネットワークのせいではありません。 |
| `tcp_blocked` | 全 TCP 接続が失敗し、すべてが Refused ではない (例えば全てタイムアウト、タイムアウトと Refused の混在、unreachable などその他の接続エラー。フィルタや到達不能が疑わしい)。DNS がどこからも引けない (NXDOMAIN ではない) 場合、つまり外向き通信が全滅しているように見える場合にも、このコードになります。その場合は画面の見出しは異なりますが、コードは同じです。 |
| `ipv6_broken` | IPv4 は通るのに IPv6 の接続が失敗する。 |
| `tls_cert_expired` | サーバの TLS 証明書の期限が切れている。 |
| `tls_cert_invalid` | TLS 証明書の検証に失敗した (チェーン検証エラーなど)。 |
| `tls_intercepted` | ミドルボックスによる TLS 傍受の疑い。 |
| `proxy_interference` | プロキシ設定があり、TCP は繋がるのに HTTP が失敗する。 |
| `unstable_path` | 経路が不安定 (パケットロスまたはジッタが大きい)。 |
| `pmtu_blackhole` | PMTUD ブラックホール。小さいパケットは通るが、経路 MTU に制限があり ICMP の通知が返らない。 |
| `udp443_blocked` | TCP・TLS・HTTP は全て正常で HTTP/3 が広告されているのに、UDP 443 (QUIC) がブロックされているように見える。 |
| `server_slow` | 接続は速いのに、サーバの最初のバイトまでの応答 (TTFB) が遅い。 |
| `server_down` | TCP 接続が全て拒否された。サーバが落ちているか、ポートが閉じている。 |
| `no_problem` | 問題は見つからなかった。 |

表の各行は独立した条件ではありません。判定ロジックの上から順に調べ、最初に当てはまったものが報告されます。例えば、ローカルとパブリックの IP 集合に重なりが無ければ、全 TCP 接続が拒否されていても `server_down` ではなく `dns_answer_mismatch` になります。

終了コードとの関係: `no_problem` の終了コードは `0` です (犯人が見つかる前に打ち切られた場合は `3`)。それ以外の値は全て `1` です。

## GitHub Actions

README と同じバージョン付き URL でビルド済みバイナリをダウンロードして実行します。終了コードだけでステップは失敗します。

```yaml
jobs:
  network-check:
    runs-on: ubuntu-latest
    env:
      VERSION: v0.6.0
    steps:
      - name: Install netblame
        run: |
          curl -fsSL "https://github.com/pathvector-studio/netblame/releases/download/$VERSION/netblame-$VERSION-x86_64-unknown-linux-musl.tar.gz" | tar xz
          ./netblame --version
      - name: Check connectivity
        run: ./netblame --lang en --max-time 30 https://example.com
```

ジョブは続行しつつ JSON レポートを保存したい場合は、終了コードを自分で受け取り、`3` を区別して扱います。(GitHub の既定シェルは `-e` 付きで動くため `|| code=$?` としています。)

```yaml
      - name: Run netblame
        run: |
          code=0
          ./netblame --json --lang en --max-time 30 https://example.com > report.json || code=$?
          echo "netblame exit code: $code"
          case "$code" in
            0) echo "no problem" ;;
            1) echo "::warning::netblame found a problem: $(jq -r .verdict.culprit_code report.json)" ;;
            3) echo "::warning::netblame timed out before reaching a verdict" ;;
            *) echo "::error::netblame failed to run (exit $code)"; exit "$code" ;;
          esac
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: netblame-report
          path: report.json
```

おすすめは、デプロイやヘルスチェックがすでに失敗したときだけ netblame を走らせ、ネットワークのどこが悪いかの証拠を残す使い方です。

```yaml
      - name: Diagnose
        if: failure()
        run: ./netblame --lang en --max-time 30 https://example.com
```

これは同じジョブ内の、インストールのステップと失敗しうるステップより後ろに置いてください。

## ほかの CI

`set -e` が有効なランナーでも `case` に届くよう、`|| code=$?` で終了コードを受け取ります。

```sh
code=0
netblame --json --lang en --max-time 30 "$TARGET" > report.json || code=$?
case "$code" in
  0) echo "ok" ;;
  1) echo "problem: $(jq -r .verdict.culprit_code report.json)"; exit 1 ;;
  3) echo "no verdict before --max-time"; exit 1 ;;
  *) echo "netblame error"; exit 2 ;;
esac
```

## 注意点

- 結果は **CI ランナーから見た** ネットワークの状態です (ホステッドランナーなら、そのランナーの DNS・経路・出口)。ユーザーやあなたの手元のネットワークではありません。
- 判定はヒューリスティックです (上のプロトタイプの注意を参照)。たまの誤検知はあり得るので、ブロックよりも報告に使うのがおすすめです。
- 提供していないもの: 閾値フラグ、「特定カテゴリのときだけ失敗」のオプション (代わりに `jq` で `.verdict.culprit_code` を絞り込んでください)、JUnit 出力、公開済みの GitHub Action。
