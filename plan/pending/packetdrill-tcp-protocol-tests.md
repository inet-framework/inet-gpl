# Run the packetdrill TCP corpus as INET protocol tests

Status: **steps 0 to 5 done 2026-09-29**; step 6 is designed; steps 6 to 8 wait for the rebase of
#1155. The `inet-gpl` side of the layout is in `packetdrill-branch-cleanup.md`.

- Branch `rh/packetdrill` of `inet-gpl`, on master `9b2fb1d`.
- INET pairing: INET `topic/tcp-new` (pull request #1155), because `PacketDrillApp` needs it
  (section 2.3).

**Names.** This plan was written before the cleanup of `packetdrill-branch-cleanup.md`, and its
records of steps 0 to 5 keep the names of that time: `tests/oracle/oracle.py` is now
`tests/packetdrill/suite.py`; *leg L* and *leg I* are the Linux run and the INET run; the *corpus*
is the two script sets, and the ids `kernel:x` and `gtests:a/b` are now `tcp/linux/x` and
`tcp/packetdrill/a/b`; the *golden* results are `tcp/linux-results.csv`; `corpus.yaml` and
`mapping.yaml` are `tcp/scripts.yaml` and `tcp/sysctls.yaml`; `ORACLE_SUSPECT` is `LINUX_SUSPECT`.
The commit hashes of the records name the history before the rewrite.

## 1. The goal

Every packetdrill script of the vendored TCP corpus that INET can run gets **one test file in
INET's `tests/protocol/tcp/`**. The file is a **wrapper**: it names the script and runs it through
`inet-gpl`, and it holds no script text. The protocol test runner runs the wrappers like any other
protocol test. A change to INET's TCP that breaks Linux-equivalent behavior then shows as a `FAIL`
in the normal test run, and not only when somebody runs the oracle scoreboard by hand.

The scripts are **not** translated into `ProtocolTester` programs. The script, the parser and the
comparison stay in `inet-gpl`; the wrapper only starts them and reads the verdict.

## 2. What exists

### 2.1 `inet-gpl`, branch `rh/packetdrill`

| Part | What it is |
| --- | --- |
| `src/inetgpl/applications/packetdrill/` | `PacketDrillApp`, extended from SCTP to TCP: the Linux kernel script dialect, the syscalls the corpus uses, a `tcp_info` bridge, `%{ }%` assertion blocks, and the comparison of outbound packets with the expected ones |
| `tests/oracle/` | a differential framework: leg L runs a script with upstream `packetdrill` on the real kernel, leg I runs it in INET, and `oracle.py compare` writes a scoreboard |
| `tests/oracle/corpus/` | 321 scripts, vendored verbatim: 159 Linux kernel selftests and 162 upstream packetdrill `gtests`, both GPL-2.0 |
| `tests/oracle/golden/7.1.3/` | the leg L result of each script on Linux 7.1.3, with the sha256 of the script it ran |
| `tests/oracle/mapping.yaml`, `corpus.yaml` | the translation of sysctls and socket options into INET parameters; the skips and the explained kernel drift |
| `tests/packetdrill/tcp/` | 10 older `.test` files, each one wraps one hand-written script and runs with `opp_test` through a local `runtest` |

The last scoreboard in the history of both repositories: **303 MATCH, 0 DIVERGENCE, 12
KERNEL_DRIFT, 3 UNSUPPORTED_FEATURE over 318 evaluated scripts.** Three scripts are skipped, all
three because they need IPv6: two force it, and one sends an ICMPv6 message.

The corpus by feature, which is also the size of the mapping work in step 5:

| Corpus | Largest groups |
| --- | --- |
| `gtests` (162) | fastopen 64, zerocopy 11, slow_start 10, shutdown 6, cubic 6, and 25 smaller groups |
| `kernel` (159) | accecn 58, fastopen 18, zerocopy 11, slow start 10, receive window 5, and 23 smaller groups |

**How leg I decides a verdict.** `PacketDrillApp` never ends the simulation; the run ends at the
time limit. A run passes when its output holds no `Packetdrill error:`, no dialect error, no stall
message and no other `<!>` error (`oracle.py`, `classify_inet_output()`).

**Leg I is more than the script.** Before a run, `oracle.py` strips the untimed preamble, turns the
sysctls into ini keys through `mapping.yaml`, and applies three rules keyed on the script: server
Fast Open when the script sets `TCP_FASTOPEN` on the listener, the explicit-read receive model for
five named scripts, and a block for a mid-script `tc qdisc`. **A wrapper must therefore run leg I
itself, not a simulation of its own**, or it gets a different verdict from the scoreboard.

### 2.2 INET protocol tests

- `tests/protocol/tcp/` holds 27 tests, named `Rfc<doc><Behavior>.test`: `opp_test` files with a
  C++ program for the `ProtocolTester`, whose descriptions cite the checks of the TCP catalogs.
- `inet_run_protocol_tests` (`opp_repl`) finds every `.test` under `tests/protocol`, including
  subfolders, and runs each one with `opp_test` in `work/` beside it. It takes the verdict from the
  `Aggregate result:` line, and a `%# expected-result: FAIL` line declares an expected failure. The
  GitHub job *Test: protocol* runs them in debug mode.
- Before it runs a test, `opp_repl` generates, makes and links a test binary for it — also for a
  test that does not need one.

Three `opp_test` features make a wrapper possible:

- `%testprog:` runs a command of the file's choice instead of the test binary, through `sh -c`, so
  `$INET_ROOT` and `$INETGPL_ROOT` expand in it. `opp_repl` appends its own simulation arguments to
  that command.
- A line `#SKIPPED: <reason>` in the output makes `opp_test` count the test as skipped.
- `%contains: stdout` checks the output for a line.

### 2.3 The dependency on INET #1155

`PacketDrillApp` uses `TcpZerocopyTag`, `TcpSendEorReq`, the Fast Open cookie cache and Accurate
ECN. All of them exist only on INET `topic/tcp-new`, not on INET master. So:

- this branch builds and runs only against `topic/tcp-new`, or against
  `topic/tcp-new-audit-fixes`, whose code is the same;
- the merge order is fixed: **#1155 into INET master, then this branch into `inet-gpl` master,
  then the wrappers into INET master.**

Both repositories need **debug** builds; leg I runs the debug library.

## 3. The decisions

### D-1 — The test files are wrappers in INET — decided 2026-09-29

**The layout, as the owner decided it on 2026-09-29 (second round):** two folders in INET, and
`inet-gpl` mirrors them with the scripts. The path of a wrapper and the path of its script are the
same, and the script's id is that path below `tests/protocol/`. The RFC-based TCP tests move into
`tests/protocol/tcp/rfc/`, and the runner is a command in INET's `bin/`, independent of TCP, so that
SCTP's scripts can use it later (third round of the owner's review, 2026-09-29).

```
INET                                          inet-gpl
bin/inet_run_packetdrill           (step 2)
tests/protocol/tcp/                           tests/protocol/tcp/
├── rfc/                                      │
│   ├── Rfc*.test              (moved)        │
│   └── TcpMutations.h         (moved)        │
├── linux/                                    ├── linux/
│   ├── README.md              (generated)    │
│   └── tcp_accecn_3rd_ack_lost.test          │   └── tcp_accecn_3rd_ack_lost.pkt
└── packetdrill/                              └── packetdrill/
    ├── README.md              (generated)
    └── fastopen/server/opt34/basic-rw.test       └── fastopen/server/opt34/basic-rw.pkt
```

`linux/` holds the scripts of the Linux kernel's selftests (158 wrappers), `packetdrill/` the
scripts of the packetdrill tool's own repository (148 wrappers). Everything else of the framework
lives in `inet-gpl` outside these folders; the cleanup plan (`packetdrill-branch-cleanup.md`)
places it and renames the rest.

The first draft flattened the names (`gtests/fastopen__server__opt34__basic-rw.test`), because
INET's own test runner extracts every test of `tests/protocol` into
`tests/protocol/work/<file name>` and 19 names repeat across the packetdrill subfolders. The mirror
keeps the subfolders instead, so **INET's runner changes to extract each test into a `work/`
folder beside it**, as `opp_repl` already does. That also ends the clash of
`element/Fragmentation.test` and `ipv4/Fragmentation.test`.

**The licence position, as the owner states it:** a wrapper is an execution script for an
`inet-gpl` test, not a copy of it. It holds no script text — no statement, no comment of the
script — so INET stays LGPL. The description of a wrapper is written by the generator from INET's
own data: the id, the provenance, the verdict and the features.

### D-2 — What a wrapper asserts — adopted as recommended

The leg I verdict only: the script passes in INET. Leg L stays in the oracle; the golden is the
provenance of each script (Linux 7.1.3 passes it), and the test run needs no kernel, no
`/dev/net/tun` and no `packetdrill` binary.

| Scoreboard verdict | Wrapper | Expected result |
| --- | --- | --- |
| `MATCH` (303) | generated | `PASS` |
| `UNSUPPORTED_FEATURE` (3) | generated | `FAIL`, and the description names the missing feature — the expected-FAIL rule allows it for an unimplemented feature |
| `DIVERGENCE` (0 today) | generated | `PASS`; the test fails until INET is repaired — a plain `FAIL`, never an expected one |
| `KERNEL_DRIFT` (12) | **not generated** | the script no longer states Linux behavior, so a pass would prove nothing; `README.md` lists each one with its reason from `corpus.yaml`, for review at the next re-pin |
| skipped (3) | not generated | `README.md` lists each one with its reason |

**306 wrappers.**

### D-3 — The wrappers are generated — adopted as recommended

A generator in `inet-gpl` writes the 306 wrappers and the `README.md` into an INET tree, from the
corpus, `corpus.yaml`, the goldens and a feature map. Nobody edits a wrapper by hand; a
per-script text lives in the data the generator reads. A check mode regenerates and compares, as
`make verify-corpus` does for the corpus.

### D-4 — "Linux equivalence" is a kind of evidence of its own — decided 2026-09-29

A packetdrill script records what **Linux** does, not what an RFC says. A pass shows that INET
behaves like Linux; where Linux deviates from an RFC, it shows that INET deviates too. So the
suite is evidence of its own kind, outside the levels of the specification-first workflow:

- The scripts never enter a catalog; the information still flows only from the standard.
- Each wrapper names the TCP features it exercises (`protocol/tcp/features.md`), so the
  conformance matrix can show a second column beside the spec-derived verdict.
- A pass that contradicts a catalog statement is a **finding** — the model follows Linux, not the
  RFC — and never counts as a pass of that statement.
- The guide gets a section on this kind of evidence (step 8).

Most of the corpus exercises documents that INET does not catalog yet: RFC 7413 (Fast Open),
RFC 3168 and Accurate ECN, RFC 8985 (RACK), RFC 6937 (PRR), RFC 9438 (CUBIC), RFC 5682 (F-RTO),
RFC 4821. The features that map to no catalog are therefore a map of where the TCP catalogs stop.

### D-5 — The licence of the corpus — confirmed 2026-09-29

`inet-gpl` is GPLv3 and the kernel selftests are GPL-2.0-only; the owner confirms that the
vendored corpus may stay in `inet-gpl`.

## 4. What one wrapper looks like

A sketch; step 3 settles the details:

`tests/protocol/tcp/packetdrill/fast_retransmit/fr-4pkt-sack.test`, in the final layout:

```
%description:

Linux equivalence: the packetdrill script tcp/packetdrill/fast_retransmit/fr-4pkt-sack,
run in INET by inet-gpl (tests/packetdrill/suite.py inet-one). This file only names
the script; the script itself is GPL-2.0 and stays in inet-gpl.

Upstream: https://github.com/google/packetdrill.git at 2c4001c4d6fc,
gtests/net/tcp/fast_retransmit/fr-4pkt-sack.pkt.
Linux 7.1.3 passes the script (script sha256 8757d3c262927209).

Features: TCP-F-FAST-RETRANSMIT
Not in INET's TCP catalogs: RFC 2018, RFC 6675

Expected result: PASS.

%# expected-result: PASS

%testprog: inet_run_packetdrill tcp/packetdrill/fast_retransmit/fr-4pkt-sack

%contains: stdout
PACKETDRILL tcp/packetdrill/fast_retransmit/fr-4pkt-sack: PASS
```

### How a wrapper finds its script

A wrapper **does refer to `inet-gpl`, but only at run time, through the environment**. It holds
the id of its script and nothing else; no path into `inet-gpl` and no script text is in the INET
tree. In the final layout the id is the script's path below `tests/protocol/`:

```
wrapper           %testprog: inet_run_packetdrill tcp/packetdrill/fast_retransmit/fr-4pkt-sack
inet_run_packetdrill  (INET bin/, on the PATH after INET's setenv)
                  $INETGPL_ROOT set?  no  -> "#SKIPPED: inet-gpl not found"
                                      yes -> $INETGPL_ROOT/tests/packetdrill/suite.py inet-one <id>
suite.py          <id> -> $INETGPL_ROOT/tests/protocol/tcp/packetdrill/fast_retransmit/fr-4pkt-sack.pkt
```

The chain as built on 2026-09-29, before the rename: `tests/protocol/tcp/packetdrill/run` and
`tests/oracle/oracle.py`, with ids like `gtests:fast_retransmit/fr-4pkt-sack` that `corpus.yaml`
resolved to `tests/oracle/corpus/gtests/`.

- `INETGPL_ROOT` comes from `inet-gpl`'s `setenv`, the same double `setenv` that the oracle already
  needs. A fallback to `$INET_ROOT/../inet-gpl` mirrors how `inet-gpl` finds INET at `../inet`,
  but it misses every worktree with a longer name, so the variable stays the primary way.
- The **script's path is the contract** between the two repositories: the same relative path
  below `tests/protocol/` names the wrapper in INET and the script in `inet-gpl`. If a script
  is added, removed or moved, the generator's check mode shows the wrapper set out of date.

Two guards keep a wrapper honest:

- The `%contains` line is required, not only the exit code: a runner that exits 0 without running
  anything must not pass.
- Without `inet-gpl`, `run` prints `#SKIPPED: inet-gpl not found` and the test counts as skipped,
  never as passed.

## 5. The steps

**Step 0 — Establish the baseline.** Build INET `topic/tcp-new` and `inet-gpl` in debug mode, run
`make test` in `tests/oracle`, and record the scoreboard and the run time of leg I. **Done when**
the scoreboard is 303 / 0 / 12 / 3, or every difference is explained.

**Run 2026-09-29, partly done.** INET `topic/tcp-new-audit-fixes` and this branch, debug, OMNeT++
OMNeT++ 6.4.0 (`3ff133c4f9`), 12 jobs under `nice`. Leg I over the whole
corpus takes **about 80 seconds**.

| Run | MATCH | CRASH | DIVERGENCE | KERNEL_DRIFT | UNSUPPORTED |
| --- | --- | --- | --- | --- | --- |
| recorded in the history | 303 | 0 | 0 | 12 | 3 |
| this branch as it was | 201 | 100 | 2 | 12 | 3 |
| after `fe7f757` | 296 | 0 | 7 | 12 | 3 |

- **The 100 crashes are explained and repaired.** All 100 were one use-after-free: six loops
  emptied a `cQueue` by removing the element that their iterator stood on, so the iterator then
  read freed memory. The result depends on the allocator, which is why the recorded run passed.
  Commit `fe7f757` pops the front instead.
- **The 7 divergences are not explained.** They are five scenarios, two of them in both corpora:
  `cubic-rto-ss-ca-cwnd-bump` and `fr-4pkt-fack-last-byte` (a packet at the wrong time — in the
  second, the tail loss probe goes out at 2.802 s where the script expects 2.202 s),
  `shutdown-rdwr-send-queue-ack-close` (a different packet), `slow-start-after-win-update` (the
  wrong time), and `tcp-info-rwnd-limited` (a stall). What they are **not**:
  - not the audit rewrite of #1155: `topic/tcp-new` itself gives the same seven;
  - not the five last commits of #1155: `a189f07c9b`, the last commit whose message claims
    "303 MATCH", gives the same seven;
  - not the parameter mapping: each of the 27 ini keys that leg I sets names a parameter that
    exists.

  What remains is the environment of the recorded run. The oracle README shows that it used
  OMNeT++'s nix shell with a `.venv`; the OMNeT++ here has none, and its last commit is three
  weeks older than the recorded runs. **Open: which INET and OMNeT++ state gave 303** — a question
  for Rudolf, or a rebuild against a newer OMNeT++.

**Accepted as the baseline on 2026-09-29 by the owner: 296 MATCH, 0 CRASH, 7 DIVERGENCE, 12
KERNEL_DRIFT, 3 UNSUPPORTED_FEATURE.** The seven stay open; they do not block the plan. A kernel
change cannot explain them, because leg L is the committed golden and leg I runs no kernel.

**Step 1 — Leg I for one script (`inet-gpl`). — done 2026-09-29.** `oracle.py inet-one
<corpus:script_id>` runs leg I through the same `run_leg_inet()` as the full leg, prints the
simulation output, and ends with `PACKETDRILL <id>: PASS` or `PACKETDRILL <id>: FAIL (<leg I
verdict>: <detail>)`. It exits 0 only on a pass, 2 on an unknown id, and prints `#SKIPPED:` for a
script that `corpus.yaml` skips. It writes nothing under `out/inet_results/`, and it gives each run
its own capture file, because `opp_repl` runs tests in parallel and `base.ini` names one file for
every run. The Python is `${PYTHON:-python3}`, as in the `Makefile`. **Done:** over the 318
evaluated scripts it gives the leg I verdict of the full run for every one, with the matching exit
status.

**Step 2 — The runner (`INET`). — done 2026-09-29**, INET `1cfa8d097a`.
`tests/protocol/tcp/packetdrill/run <id>` prints the `#SKIPPED` line when `INETGPL_ROOT` is not set
or holds no `tests/oracle`, and otherwise hands the id to `oracle.py inet-one`. It ignores the
simulation arguments that `opp_repl` appends. **Done:** a pass, a fail and a skip, on three chosen
scripts.

A wrapper reaches `run` through **`$INET_ROOT`**. A relative path does not work: INET's own test
runner (`python/inet/test/opp.py`, which the GitHub job uses) starts a test in
`tests/protocol/work/<file name>/`, and `opp_repl` starts it in `work/<file name>/` beside the
`.test` file. `INET_ROOT` is always set when a wrapper can run at all, because INET's runner finds
the project through it and `oracle.py` refuses to run without it.

The INET commits name a plan inside INET, as PR-MSG-PLAN requires, so the INET branch carries a
short plan of its own with the INET steps; this file stays the design.

**Step 3 — The generator (`inet-gpl`). — done 2026-09-29.** `oracle.py gen-wrappers --into
<dir> [--check]`. The expected result comes from `prepare_leg_inet()`, the preparation of leg I
moved into a function of its own, so the three expected failures follow from the same rules as the
run; the scoreboard is unchanged by the move (296 / 0 / 7 / 12 / 3). `corpus.yaml` gains the
upstream repository and path of each corpus, which a wrapper names. **Done:** 306 wrappers, 3 of
them expecting `FAIL`, and 15 scripts without one (12 drift, 3 skipped); `--check` is clean after a
second run; no wrapper holds any line of 12 characters or more from its script. With INET's own
runner (`inet_run_protocol_tests -p inet`), a pass, an expected failure, a divergence and a kernel
wrapper give PASS, FAIL (expected), FAIL (unexpected) and PASS.

**Found on the way, not ours to repair here:** two existing INET tests share a file name,
`element/Fragmentation.test` and `ipv4/Fragmentation.test`, so under INET's runner they share
`tests/protocol/work/Fragmentation/` and can clobber each other when run together.

**Found for step 4:** without `inet-gpl`, `opp_test` marks the test `SKIPPED` but prints
`Aggregate result: PASS`, and `opp_repl` reads only that line. A missing `inet-gpl` would read as
306 passes. Step 4 must report such a test as `SKIP`.

**Step 4 — The runner does not build what it does not need, and a skip is a skip. — done
2026-09-29.** INET has its own copy of the runner (`python/inet/test/opp.py`, used by
`inet_run_protocol_tests` and the GitHub job) beside `opp_repl`'s, so both changed: INET
`ec5d3484db` on `topic/tcp-packetdrill-tests`, `opp_repl` `3100802` on `main` (not pushed). Both
give 296 PASS, 3 FAIL (expected) and 7 FAIL (unexpected) over the 306 wrappers with `inet-gpl`,
and 306 SKIP without it; INET's runner needs 14 seconds on 12 cores.

The original text of the step: For a test that declares `%testprog`, `opp_repl` skips the generation, the makefile
and the link, which would otherwise cost 306 needless links per run. A test that `opp_test` marks
`SKIPPED` arrives as `SKIP`, not as the `PASS` of the aggregate line.
**Done when** `inet_run_protocol_tests --filter packetdrill` reports 303 `PASS` and 3 expected
`FAIL` with `inet-gpl` present, and 306 `SKIP` without it.

**Step 5 — The features. — done 2026-09-29.** `tests/oracle/features.yaml` maps each category
that `categorize()` gives (the `gtests` subfolder, the `kernel` file prefix) to what its scripts
are about: ids of INET's TCP feature map (`TCP-F-*`, on INET master), a document that INET's TCP
evidence does not catalog, or a Linux socket interface that no standard defines. A `scripts` entry
refines a category; the only one so far gives `slow-start-after-idle` the restart after idle. A
category without an entry stops the generator. **Done:** every wrapper has a `Features:` line, and
the `README.md` tallies all three kinds. 11 of the 23 TCP features appear, in 74 assignments; the
largest uncatalogued documents are RFC 7413 (80 wrappers) and RFC 9768 (58), and the largest
Linux interface is `MSG_ZEROCOPY` (21).

The feature ids point into `doc/project/evidence/`, which the INET branch does not have until its
rebase onto master.

**Step 6 — CI. — designed 2026-09-29; lands after the rebase of #1155.** At this branch's base the
protocol tests run in the matrix of `.github/workflows/other-tests.yml`; master split it into one
workflow per category (`4fda03f612`), so a change here would be replaced at the rebase. The change
to master's `protocol-tests.yml`:

```yaml
      - uses: actions/checkout@v6
        with:
          repository: inet-framework/inet-gpl
          path: inet-gpl
          ref: rh/packetdrill            # master, once rh/packetdrill merges
```

and, in the *Build and test* step, after `build-inet.sh` and before `inet_run_protocol_tests`:

```sh
echo "::group::Building inet-gpl"
python3 -m pip install pyyaml            # oracle.py reads corpus.yaml and mapping.yaml
cd $GITHUB_WORKSPACE/inet-gpl && . setenv -q && make makefiles && make MODE=$MODE -j $(nproc)
make -C tests/oracle build
echo "::endgroup::"
echo "::group::Checking that the packetdrill wrappers can run"
"$INET_ROOT/tests/protocol/tcp/packetdrill/run" gtests:fast_retransmit/fr-4pkt-sack | tail -1 \
  | grep -qx 'PACKETDRILL gtests:fast_retransmit/fr-4pkt-sack: PASS'
echo "::endgroup::"
```

**The guard** runs one script that passes and requires its verdict line, so a job in which
`inet-gpl` is missing or broken fails at once instead of turning 306 wrappers into 306 skips.
Checked locally: it passes with `inet-gpl` and fails without it.

**The job will be red** while the seven baseline divergences stand: under D-2 each one is a plain
`FAIL`, not an expected one. Repairing or explaining them is what turns the job green.

**Steps 7 and 8 land after the rebase of #1155.** The INET branch sits on #1155's old base, which
predates `doc/project/evidence/` and the guide, so these two steps go onto the rebased branch or a
branch of their own from master.

**Step 7 — The evidence (`INET`).** `model/tcp/results.md` gets a Linux equivalence section that
cites the suite by commit, and `conformance.md` gets the second column of D-4. **Done when** every
TCP feature shows its equivalence verdict, or says that no script exercises it.

**Step 8 — The guide (`INET`).** A section in `derive-tests-from-a-standard.md` on implementation
oracle evidence: where it goes, and what it may not claim. **Done when** the guide says both.

**Where the work lands.** Steps 1, 3 and 5 on this branch. Step 4 in `opp_repl`. Steps 2, 6, 7
and 8, and the generated wrappers, on an INET branch **based on `topic/tcp-new-audit-fixes`**
(decided 2026-09-29), so that the wrappers run during development. The proposed name is
`topic/tcp-packetdrill-tests`, with the worktree `inet-tcp-packetdrill-tests`.

## 6. Risks

- **#1155 has not merged.** Everything pairs with `topic/tcp-new` until it does, and the merge
  order of section 2.3 holds. The audit fixes of #1155 keep the code the same, so the pairing
  survives them.
- **The timing tolerance is wide.** Leg I accepts a packet up to 0.5 s from its scripted time,
  which is generous by design at bring-up. A wrapper that passes at this tolerance can still be far
  from Linux. Tightening it is follow-up work, one group at a time, and each change moves verdicts.
- **Run time.** 306 simulations per protocol test run; step 0 measures leg I, step 4 the overhead
  of the runner.
- **The Python of the runner.** `oracle.py` needs PyYAML, and the `python3` on the `PATH` may not
  have it (the oracle README describes this). Step 1 resolves it in one place.
- **The 10 older tests** in `inet-gpl` `tests/packetdrill/tcp` use their own scripts and stay as
  they are.
