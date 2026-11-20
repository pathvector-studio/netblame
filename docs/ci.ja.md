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
| `3` | **犯人を特定する前に** 打ち切られた (`--max-time` の期限切れ、または Ctrl-C / SIGINT)。`--max-time` の期限時点で犯人が特定済みなら終了コードは `1` です。Ctrl-C は途中結果を捨てて常に `3` です。`--watch` は例外です (下記参照)。 |

`--share` は終了コードを変えません。アップロードに失敗しても stderr に警告が出るだけです。

CI で `--watch` は使わないでください。Ctrl-C まで診断を繰り返し続け、`--json` とも併用できません (終了コード `2`)。`--max-time` は watch 内の各回に適用されるだけで、ループ自体は止まりません。`--watch` では終了コードが異なります。終了するのは Ctrl-C のときだけで、期間中に犯人を特定した回が 1 度でもあれば `1`、なければ `0` で、`3` にはなりません。Ctrl-C で中断された回は破棄されて集計に含まれず、`--max-time` で打ち切られて犯人が見つからなかった回は問題なしとして数えられます。

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
| `.verdict.culprit_code` | ロケール非依存の snake_case コード。例: `"no_problem"`、`"local_dns_broken"`、`"server_down"`。**スクリプトではこれを使ってください。** |
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
