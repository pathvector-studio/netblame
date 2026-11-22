# Using netblame in CI

English | [日本語](ci.ja.md)

netblame is a plain CLI that reports its result through its **exit code** and, with `--json`, a machine-readable report. That is all a CI job needs: any system that can check `$?` can use it. There is no dedicated GitHub Action, threshold option or JUnit output; the examples below use only exit codes and `jq`.

> ⚠️ **Prototype.** Verdict thresholds are heuristics, so a failing check can be a false alarm. Treat netblame in CI as a smoke check, or as a way to **collect evidence when something already failed**, rather than as a hard merge gate.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No problem (the verdict is `no_problem`). Secondary notes alone do not change this. |
| `1` | A culprit was identified. This includes `name_does_not_exist` (NXDOMAIN) and `server_down`; every verdict other than `no_problem` is `1`. |
| `2` | Usage or internal error (e.g. unparseable target, `--json` combined with `--watch`, JSON serialization failure). |
| `3` | The run was cut short (`--max-time` expired, or Ctrl-C/SIGINT) **before any culprit was identified**. If a culprit was already found when `--max-time` expired, the exit code is `1`. Ctrl-C discards partial results and exits `3` only while the diagnosis is running (see "Other ways the process can exit" below), and with `--json` a JSON serialization failure exits `2`. `--watch` is the exception (see below). |

`--share` never changes the exit code; an upload failure only prints a warning to stderr.

Do not use `--watch` in CI. It repeats the diagnosis until Ctrl-C and cannot be combined with `--json` (exit `2`). `--max-time` applies to each run inside it and does not stop the loop. Exit codes differ in `--watch`: Ctrl-C is the only way to stop it, and the exit code is `1` if any run during the session found a culprit, otherwise `0`; it is never `3`. A run interrupted by Ctrl-C is discarded and not counted, and a run cut short by `--max-time` without a culprit counts as no problem.

### Other ways the process can exit

- A signal other than Ctrl-C (SIGINT), such as SIGTERM, ends the process by that signal, and its exit status is not one of the codes above (e.g. 143 in a shell).
- Ctrl-C (SIGINT) that arrives very early, before the diagnosis starts, is not handled by netblame yet: the process ends by that signal (`130` in a shell) instead of exiting `3` (in `--watch`, instead of `0` or `1`). This window lasts from process start (argument parsing) until the diagnosis begins, i.e. it still includes the moment right after the `diagnosing ...` line (with `--watch`, the `watching every ...` line) is printed.
- Ctrl-C (SIGINT) that arrives after the diagnosis has finished is ignored: once netblame has started listening for Ctrl-C the OS default action (terminate) is not restored, and nothing is listening any more. The process does not stop and exits as usual (`0`/`1`/`2`, not `3`), after the result is printed and, with `--share`, after the upload ends (the upload cannot be interrupted with Ctrl-C). The same goes for a second Ctrl-C while the report cut short by the first Ctrl-C is being built and printed (the exit code stays `3`). In `--watch`, a Ctrl-C that arrives while a run's result is being printed (between runs) is ignored the same way, as is one during the final summary.
- A panic on the main task (the task running `main`) ends the process with `101`, which is not one of the codes above. A panic inside the blocking tasks used by netblame's own DNS and trace probes is caught as a join error and the diagnosis continues. How a panic inside a task that a dependency library (hickory-resolver, reqwest, quinn, etc.) starts internally is handled depends on that library: it may be swallowed and the run continues, or it may be propagated to the caller and end in `101`. In every case Rust's default panic hook still prints the panic message to stderr.

## Flags worth setting in CI

- `--max-time <secs>`: an overall deadline that is checked only **between stages**; it does not interrupt a stage that is already running. Once the deadline has passed, the stages not yet started are skipped, a partial report is still printed, and the exit code is `3` if no culprit was found by then. The running stage always finishes first, so the run can overshoot `--max-time` by up to the length of that stage. Most network stages are bounded by `--timeout <secs>` (default 5, per probe); the trace stage does not take `--timeout` and has its own internal limit of about 75 seconds. Use `--max-time` together with `--timeout` (and a CI-side job timeout as a hard limit) rather than as an exact cap.
- `--json`: prints one JSON document to stdout. Nothing else is written to stdout in this mode, so piping into `jq` works (except with `--share`, which prints the share URL to stdout after the JSON; avoid combining it with `| jq`). Warnings (e.g. a failed `--share` upload) go to stderr.
- `--lang en`: fixes the language of the text. Without it, the language is picked from `LC_ALL`, `LC_MESSAGES`, `LANG`.
- `--no-color`: disables color. Color is also turned off automatically when stdout is not a terminal, which is the case in most CI logs.
- `--trace`: always run the hop-level path trace (Linux only). Without it, the trace runs only when an earlier stage found a path problem.

## JSON fields

The top level has two keys, `report` and `verdict`.

| Path | Value |
|---|---|
| `.verdict.culprit_code` | Locale-independent snake_case code such as `"no_problem"`, `"local_dns_broken"`, `"server_down"`. **Use this for scripting.** |
| `.verdict.culprit` | The same category spelled as the variant name, e.g. `"NoProblem"`. |
| `.verdict.headline`, `.evidence`, `.next_step`, `.secondary` | Human-readable text (in the chosen `--lang`). `evidence` and `secondary` are arrays of strings. |
| `.report.completeness.complete` | `false` if the run was cut short. |
| `.report.completeness.truncated_reason` | `null`, `"max_time_exceeded"` or `"interrupted"`. |
| `.report.completeness.ran_stages`, `.skipped_stages` | Arrays of stage names (`env`, `dns`, `tcp`, `tls`, `http`, `quic`, `path`, `trace`). |
| `.report.stage_durations` | Array of `{"stage": "...", "ms": 12.3}`, in execution order. |

```bash
netblame --json --lang en --max-time 30 https://example.com > report.json || true   # exit 1/3 are results, not crashes (matters under `set -e`); note it also swallows exit 2 (usage/internal error)
jq -r '.verdict.culprit_code' report.json
jq -r '.report.stage_durations[] | "\(.stage)\t\(.ms)"' report.json
jq -e '.report.completeness.complete' report.json   # for detecting truncation: exits 1 if truncated (this stops a script running under `set -e`)
```

## GitHub Actions

Download the prebuilt binary with the same versioned URL as the README, then run it. The exit code fails the step on its own.

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

To keep the job going but save the JSON report, capture the exit code yourself and treat `3` separately. (GitHub's default shell runs with `-e`, hence the `|| code=$?`.)

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

A good pattern is to run netblame only when a deploy or health check has already failed, to capture where the network is at fault:

```yaml
      - name: Diagnose
        if: failure()
        run: ./netblame --lang en --max-time 30 https://example.com
```

Place that after the install step (and the failing step) in the same job.

## Other CI systems

Capture the exit code with `|| code=$?` so that a runner using `set -e` does not stop the script before the `case`.

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

## Caveats

- The result describes the network **as seen from the CI runner** (for hosted runners: their DNS, routes and egress), not your users' or your laptop's.
- Verdicts are heuristics (see the prototype note above). Expect the occasional false alarm, and prefer reporting over blocking.
- Not provided: a threshold flag, a "fail on category X only" option (filter on `.verdict.culprit_code` with `jq` instead), JUnit output, or a published GitHub Action.
