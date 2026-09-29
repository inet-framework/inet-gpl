# Make `rh/packetdrill` ready for `inet-gpl` master

Status: **S1 to S4 done, and the branch merged into `master` 2026-09-29** (S6, before S5 and
before #1155 reaches INET master, at the owner's request). INET's branch
`topic/tcp-packetdrill-tests` holds S4. S5 is open. All decisions are made.

- Branch `rh/packetdrill`, on `inet-gpl` master `9b2fb1d` (0 behind it).
- Companion plan: `packetdrill-tcp-protocol-tests.md` (the INET wrappers), which this branch serves.

## 1. The goal

`rh/packetdrill` merges into `inet-gpl` master as a series in which every name says what it
names, every commit holds one concern and builds, nothing names a local path or a document outside
the repository, and the tests pass or state why not. It merges after INET #1155 (F1).

The changes under `src/` are good and stay as they are. The hand-written packetdrill suites of
`inet-gpl` for TCP, UDP and SCTP are deleted: the TCP scripts of Linux and of packetdrill, and
INET's standards-based TCP and UDP tests, cover more. The real SCTP packetdrill tests come later.

## 2. What the branch held before S2

| # | Commits | Author | What |
| --- | --- | --- | --- |
| 1–6 | `394222b` … `d17586e` | Rudolf Hornig | `PacketDrillApp` extended from SCTP to TCP: the Linux dialect, the TCP connection model, the syscalls, `tcp_info` and `%{ }%`, expected-packet comparison |
| 7–9 | `5b05f19`, `9d15b9f`, `f63c070` | Rudolf Hornig | the framework under `tests/oracle` with 318 JSON results, then relative corpus paths, then the vendored corpus |
| 10–22 | `f2829c9` … `61d2315` | Levente Meszaros | one fix (`fe7f757`, a use-after-free), five framework changes (`inet-one`, `gen-wrappers`, the feature map, Linux's retransmission timer, and Linux's initial window and ICMP reaction for the INET run), and plan commits |

Rudolf's messages are strong: 18 to 66 lines of body each, with reasons.

## 3. The layout

### INET

```
bin/
└── inet_run_packetdrill             runs one packetdrill script through inet-gpl, or prints
                                     #SKIPPED; the same command for every protocol

tests/protocol/tcp/
├── rfc/                             the 27 tests derived from the RFCs, moved here
│   ├── Rfc5681FastRetransmit.test
│   ├── ...
│   ├── Rfc9293ValidReset.test
│   └── TcpMutations.h               included by 11 of them, so it moves with them
├── linux/                           158 wrappers, one per script of the Linux kernel's selftests
│   ├── README.md                    generated: what the wrappers are, the scripts without one
│   ├── tcp_accecn_3rd_ack_lost.test
│   └── ...                          flat, as the scripts are
└── packetdrill/                     148 wrappers, one per script of the packetdrill repository
    ├── README.md                    generated, as above
    ├── blocking/blocking-accept.test
    ├── fastopen/
    │   ├── client/*.test
    │   └── server/
    │       ├── *.test
    │       └── opt34/basic-rw.test
    └── ...                          the same 31 feature folders as the scripts
```

### `inet-gpl`

```
tests/
├── fingerprint/                     unchanged
├── statistical/                     unchanged
├── protocol/                        the scripts, in INET's structure; nothing but .pkt files
│   └── tcp/
│       ├── linux/                   159 scripts from the Linux kernel's selftests, flat
│       │   └── tcp_*.pkt
│       └── packetdrill/             162 scripts from the packetdrill repository
│           ├── blocking/            4      ├── md5/                 1
│           ├── close/               3      ├── mss/                 3
│           ├── cubic/               6      ├── mtu_probe/           2
│           ├── cwnd_moderation/     2      ├── nagle/               3
│           ├── ecn/                 1      ├── notsent_lowat/       3
│           ├── eor/                 4      ├── sack/                4
│           ├── epoll/               4      ├── sendfile/            1
│           ├── fast_recovery/       4      ├── shutdown/            6
│           ├── fast_retransmit/     4      ├── slow_start/         10
│           ├── fastopen/                   ├── splice/              1
│           │   ├── client/         29      ├── syscall_bad_arg/     3
│           │   └── server/         19      ├── tcp_info/            3
│           │       └── opt34/      16      ├── timestamping/        3
│           ├── gro/                 1      ├── ts_recent/           3
│           ├── inq/                 2      ├── user_timeout/        2
│           ├── ioctl/               1      ├── validate/            1
│           ├── limited_transmit/    2      └── zerocopy/           11
│           └── (the numbers count scripts)
└── packetdrill/                     everything else: the generic tool, and TCP's part in tcp/
    ├── README.md                    how a script runs in INET and on Linux, the pitfalls
    ├── Makefile                     targets: inet, linux, report, test, verify-scripts, build, ...;
    │                                PROTOCOL=tcp selects the protocol folder
    ├── suite.py                     linux | inet | inet-one | compare | verify-scripts | gen-wrappers
    ├── .gitignore                   build/, out/, __pycache__/
    ├── ini/
    │   └── base.ini                 the host, the tun interface, the pcap recorder (21 keys)
    ├── ned/
    │   ├── PacketDrillNetwork.ned   one PacketDrillHost, nothing protocol-specific
    │   └── pdhost.mrt
    └── tcp/
        ├── README.md                the two TCP sets: provenance, licence, scoreboard, the seven
        │                            divergences
        ├── tcp.ini                  the Linux behaviors that no preamble sysctl states, as INET
        │                            parameters
        ├── tcp.py                   the TCP rules of the tool: the sysctl preamble, the Fast Open
        │                            listener, the explicit-read scripts, tc qdisc, tcp_cubic's
        │                            module parameters, the kernel source hints, the categories
        ├── scripts.yaml             the upstream pins, the defaults every script runs under,
        │                            the skips, the kernel drift
        ├── linux-results.csv        the Linux run on the pinned kernel: one row per script
        ├── sysctls.yaml             Linux sysctls and socket options -> INET's Tcp parameters
        ├── features.yaml            script folder -> INET TCP features, documents, Linux interfaces
        └── set_sysctls.py           Google's; placed where its callers expect it by the Linux run

removed:  tests/oracle/                      moved into tests/protocol/tcp/ and tests/packetdrill/
          tests/packetdrill/{sctp,tcp,udp}/  the hand-written suites: 28 tests, 39 scripts, and
                                             packetdrill.tar.gz
ignored run artifacts: tests/packetdrill/build/ (the runner packetdrill_inet), tests/packetdrill/out/
```

### How the pieces fit

**A script's id is its path below `tests/protocol/`.** `tcp/linux/tcp_accecn_3rd_ack_lost` names
`inet-gpl/tests/protocol/tcp/linux/tcp_accecn_3rd_ack_lost.pkt` and
`inet/tests/protocol/tcp/linux/tcp_accecn_3rd_ack_lost.test` at once. The protocol is part of the
id, so SCTP's scripts fit the same runner later (`sctp/packetdrill/...`). No table maps one tree to
the other. `inet-gpl` mirrors only `linux/` and `packetdrill/`; `rfc/` is INET's alone.

**The runner in INET.** A wrapper cannot call `inet-gpl` directly: with `INETGPL_ROOT` unset, the
path is wrong and `opp_test` reports an error, not a skip. `bin/inet_run_packetdrill` turns a
missing `inet-gpl` into `#SKIPPED`, and otherwise hands the id to `suite.py inet-one`. It lives
beside the other `inet_*` commands, which INET's `setenv` puts on the `PATH`, so a wrapper names it
without a path:

```
%testprog: inet_run_packetdrill tcp/packetdrill/fast_retransmit/fr-4pkt-sack
%contains: stdout
PACKETDRILL tcp/packetdrill/fast_retransmit/fr-4pkt-sack: PASS
```

**The wrapper folders under INET's runner.** INET's own runner (`python/inet/test/opp.py`) extracts
every test of `tests/protocol` into `tests/protocol/work/<file name>`, so two tests with one file
name share a folder. The packetdrill set has 19 names that repeat across its folders
(`fastopen/server/basic-rw`, `fastopen/server/opt34/basic-rw`, ...). The runner must extract each
test into a `work/` folder beside it, as `opp_repl` already does. That also repairs the existing
clash of `element/Fragmentation.test` and `ipv4/Fragmentation.test`.

**The generic tool and TCP's part.** Of the framework's files, the script pins, the Linux results,
the sysctl map, the feature map and the helpers are TCP's alone; `base.ini` is half TCP's (23 of
its 44 keys are `**.tcp.*`), and so are parts of the tool; the NED network and its routing file
hold nothing of TCP. The TCP half of `base.ini` becomes `tcp/tcp.ini`, and the TCP rules of the
tool move behind a small interface into `tcp/tcp.py`. The SCTP migration then adds `sctp/` beside
`tcp/` and changes nothing at the top.

**The preamble every script sources.** All 321 scripts source a `defaults.sh` by a relative path:
the 159 Linux scripts `./defaults.sh`, the packetdrill scripts `../common/`, `../../common/` or
`../../../common/` by their depth, 29 of them a `common/` folder one level above the whole set. 58
scripts also call `set_sysctls.py` with arguments (11 Linux, 47 packetdrill). Only the Linux run
executes these files; the INET run strips them. Upstream has five such files:

- three `defaults.sh` that are data: two commands and 22 or 23 sysctls. The Linux variant and the
  packetdrill variant share 21 settings and differ in two, `tcp_fastopen` (`0x3`, `0x70403`) and
  `tcp_ecn_option` (not set, `2`); the third file is a byte-identical copy of the packetdrill
  variant;
- two `set_sysctls.py` that are code: 20 lines of Google's that set sysctls through `/proc` and
  write a restore script; the two copies differ only in their header comment.

**So the defaults become data in `tcp/scripts.yaml`, the one source for both runs**, and one
`set_sysctls.py` remains:

```yaml
# What every script's preamble sets up on Linux: upstream's defaults.sh, as data. All 321
# scripts source it. The Linux run writes it out as defaults.sh; the INET run translates
# the sysctls through sysctls.yaml.
defaults:
  commands:
    - ip tcp_metrics flush all
    - tc qdisc add dev tun0 root pfifo
  sysctls:                                   # the 21 settings both sets share
    net.ipv4.tcp_rmem: "4096 540000 15728640"
    net.ipv4.tcp_wmem: "4096 262144 4194304"
    net.ipv4.tcp_sack: "1"
    ...
  sets:                                      # where the two upstream files differ
    linux:
      net.ipv4.tcp_fastopen: "0x3"
    packetdrill:
      net.ipv4.tcp_fastopen: "0x70403"
      net.ipv4.tcp_ecn_option: "2"
  kernel:                                    # Linux's own defaults that no preamble sets,
    net.ipv4.tcp_window_scaling: "1"         # but that the INET run must mirror
```

The Linux run copies the scripts into a temporary tree of upstream's shape, writes each set's
`defaults.sh` there from this block, places `set_sysctls.py` where its callers expect it, and runs
there. The INET run takes the same sysctls from the block, so the hand copy in `sysctls.yaml` goes
(F9), and `tcp.ini` drops each key that a preamble now states; the scoreboard checks every key it
drops. A re-pin reads upstream's `defaults.sh` at the old and the new commit and applies the
difference to the block.

**One Linux summary instead of 318 results.** A result file holds the script's id, its sha256, the
verdict, the duration and the path of the packetdrill binary -- a personal profile path in all 318.
What the framework needs is the verdict of each script on the pinned kernel, and the sha256 that
`verify-scripts` checks. `linux-results.csv` holds exactly that, one row per script, with a header
that names the kernel release, the packetdrill commit and the date of the run. A re-record on a new
kernel rewrites the file; the history keeps the old one. The moves change no script, so no sha256
changes.

### The names

| Now | Final | Why |
| --- | --- | --- |
| `tests/oracle/corpus/kernel/*.pkt` | `tests/protocol/tcp/linux/*.pkt` | the scripts of the Linux kernel's selftests |
| `tests/oracle/corpus/gtests/**.pkt` | `tests/protocol/tcp/packetdrill/**.pkt` | the scripts of the packetdrill tool's own repository; *gtests* is only upstream's folder name |
| script ids `kernel:x`, `gtests:a/b` | `tcp/linux/x`, `tcp/packetdrill/a/b` | the id is the path below `tests/protocol/` |
| `tests/oracle/` (the rest) | `tests/packetdrill/` | the machinery that runs packetdrill scripts, in the folder the deleted suites free |
| `oracle.py` | `suite.py` and `tcp/tcp.py` | the generic tool and the TCP rules |
| *leg L*, *leg I*; targets `legl`, `legi`; verdicts `L_PASS`, `I_PASS`, ... | *the Linux run*, *the INET run*; targets `linux`, `inet`; verdicts `LINUX_PASS`, `INET_PASS`, ... | a reader who has not seen the design cannot guess what a leg is |
| `corpus.yaml` | `tcp/scripts.yaml` | the pins, the defaults, the skips and the kernel drift of the scripts |
| the three `defaults.sh` | the `defaults:` block of `tcp/scripts.yaml` | data, one source for both runs |
| the two `set_sysctls.py` | `tcp/set_sysctls.py` | code; one copy |
| `golden/7.1.3/*.json`, 318 files | `tcp/linux-results.csv` | one summary |
| `mapping.yaml` | `tcp/sysctls.yaml`, without `known_preambles` | it translates Linux sysctls and socket options into INET parameters, nothing else |
| `features.yaml` | `tcp/features.yaml` | TCP's |
| `corpus/README.md` | `tcp/README.md` | the scripts' folders hold nothing but scripts |
| `ini/base.ini` | `ini/base.ini` (generic keys) and `tcp/tcp.ini` | the TCP half moves |
| `ned/OracleTcpHost.ned` | `ned/PacketDrillNetwork.ned` | one `PacketDrillHost`; nothing in it is TCP's |
| `ned/pdhost.mrt` | unchanged | |
| the runner `oracle_exe` | `packetdrill_inet` | the simulation executable of the INET run; not `packetdrill`, which is upstream's binary that the Linux run calls |
| INET `tests/protocol/tcp/packetdrill/run` | INET `bin/inet_run_packetdrill` | independent of TCP; on the `PATH` like every `inet_*` command |
| INET `tests/protocol/tcp/Rfc*.test`, `TcpMutations.h` | INET `tests/protocol/tcp/rfc/` | three kinds of TCP test in three folders |

## 4. The findings

### The history

- **F1 — The branch needs INET #1155.** `PacketDrillApp` uses `TcpZerocopyTag`, `TcpSendEorReq`,
  the Fast Open cookie cache and Accurate ECN, which exist only on the #1155 branch. It merges
  after #1155 merges into INET master.
- **F2 — The framework arrives in three states.** Commit 7 has the paths of one machine
  (a folder of one developer's home), commit 8 makes them relative to a sibling folder, commit 9 vendors
  the scripts. Only the last state is the design, and the new layout replaces all three names.
- **F3 — The use-after-free fix (`fe7f757`) sits after the framework**, although the code it
  repairs is older than the branch. Its place is beside the other `PacketDrillApp` commits.
- **F4 — Plan commits sit among the code**, and the plans name local paths of one developer's
  workspace.
- **F5 — Commit 1 edits the hand-written TCP suite** (its `runtest` and its NED import). S2 keeps
  those hunks: commit 1 comes before the deletion, because master does not build without it (F10).

### The tree

- **F6 — The README names three documents outside the repository**: the implementation plan, the
  feasibility recon, and a debugging session called "required reading before touching that code".
  A reader of master can follow none of them.
- **F7 — The README states an old scoreboard**: the 2026-07-11 baseline, and 303 MATCH in the
  history. The accepted baseline of 2026-09-29 is 296 MATCH, 0 CRASH, 7 DIVERGENCE,
  12 KERNEL_DRIFT, 3 UNSUPPORTED_FEATURE, with the seven not explained.
- **F8 — Two texts name the deleted suites**: `src/inetgpl/applications/packetdrill/README`
  ("see the 'tests/packetdrill' directory") and a comment in `oracle.py`. Both follow the move.
- **F9 — The INET run keeps a hand copy of the defaults, and it has drifted.** `mapping.yaml`'s
  `known_preambles` repeat each variant's sysctls. The copy of the packetdrill variant lacks 4 of
  its 23 settings (`tcp_fastopen`, `tcp_fastopen_key`, `tcp_notsent_lowat`, `tcp_syncookies`), and
  its comment calls it the Linux variant plus `tcp_ecn_option`, which is wrong. No verdict moves
  only because `base.ini` hard-codes the same Fast Open values for every script: the same facts
  stand in three places, and one is wrong. Sourcing each `defaults.sh` with stub `sysctl`, `ip` and
  `tc` functions gives its 22 and 23 settings exactly, the source the `defaults:` block starts from.

### The source code -- stays as it is

Three things were found under `src/`, for the owner to take or leave; none blocks the merge:

- **F10 — `inet-gpl` master is broken against INET master today.** INET master no longer has
  `TcpIpChecksum.h`, and `tcp_nsc` on master still includes it. Commit 1 of this branch repairs it.
- **F11 — Two compiler warnings from the branch**: `PacketDrillApp.cc:4269` (`-Wswitch`, a case
  value outside `TcpOptionNumbers`) and `parser.y:104` (`current_script_line` set but not used).
- **F12 — Objects outlive a run.** A passing run ends with up to 3 "undisposed object" messages, a
  failing one with more.

### Found during S1 and S3

- **F16 — The licences differ.** `inet-gpl`'s `LICENSE` is GPL-3.0. The Linux scripts are GPL-2.0
  (101 of 159 have `SPDX-License-Identifier: GPL-2.0`, the kernel's `COPYING` covers the others),
  and upstream packetdrill's `LICENSE` is GPL-2.0; its scripts have no header. The old corpus
  README called this "compatible". The new `tcp/README.md` states only the facts: the scripts
  keep their licence and are input files that no program of the repository includes. Confirmed
  by the owner on 2026-09-29.
- **F17 — The generated parser has old line numbers.** A new generation from `parser.y` and
  `lexer.l` with bison 3.8.2 and flex 2.6.4 gives the same code as the committed `parser.cc` and
  `lexer.cc`, but other `#line` directives and another line table: about 1300 lines in
  `parser.cc` and 360 in `lexer.cc`. `parser.y` also has four comment lines that name
  `oracle.py` and the legs. The owner approved a new generation on 2026-09-29; S2 puts it, with
  the corrected comments, into the dialect commit, the only commit that changes the parser.
- **F18 — "corpus" stays in 27 comment lines under `src/`** as a plain word for the scripts. The
  comments that named dead files or verdicts, and twelve that named the work packages of #1155's
  plan ("Workstream F", "H2"), are corrected by S2 in the commits that wrote them.
- **F19 — The tool files had more leftovers** than the names: a local kernel path
  (`kernel_source_root`), fallback commits of a July run, an `overrides` key without a reader, and
  comments that named the recon, the milestones, the handoff report and the work packages.
  All removed.

### Found during S2

- **F20 — The owner's six commits did not build one by one.** The parser of commit 2 (the
  dialect) calls `PacketDrill::buildICMPPacket` and a `buildTCPPacket` with 11 arguments, which
  commit 6 adds; commits 2 to 5 failed with these two errors in `parser.o`, and with no other. S2
  moves the changes of commit 6 in `PacketDrill.cc` and `PacketDrill.h` (the packet construction)
  into commit 2, with their paragraph of the message; commit 6 keeps its changes in
  `PacketDrillApp.cc` (the injection into the live connection, and the comparison).
- **F21 — A second session committed on the old layout.** `61d2315` (the initial window and the
  ICMP reaction, in `tests/oracle/ini/base.ini`) came after `19b7acf`, and that session pushed
  `rh/packetdrill` to `origin` at `61d2315`. S2 puts the two keys into `tcp/tcp.ini` as a commit of
  their own. A session that commits on the old layout after the force-push needs the new paths.
- **F22 — The INET baseline moved.** #1155 is rebased; its tip on 2026-09-29 is `359db08cc3`. S2 is
  checked against it: the scoreboard is 297 MATCH, 6 DIVERGENCE, 12 KERNEL_DRIFT and
  3 UNSUPPORTED_FEATURE. `shutdown/shutdown-rdwr-send-queue-ack-close` passes since INET
  `c23267fa9b`, which cancels the loss probe when all outstanding data is acknowledged.

### What is left open

- **F13 — `inet-gpl`'s own baselines move with #1155.** `tests/fingerprint/external-tcpip.csv`
  compares INET's TCP with the NSC stack, and `examples.csv` holds examples that run INET's TCP.
  These rows move and need re-recording with an explanation.
- **F14 — The SCTP path of `PacketDrillApp` has no test until the SCTP migration.** Commit 1
  changed the app's SCTP assumptions, and the hand-written SCTP suite was its only test. The owner
  accepts the gap; the SCTP packetdrill tests come later, into `tests/protocol/sctp/`.
- **F15 — `inet-gpl` has no CI.** The TCP scripts get theirs through INET's protocol job (the
  companion plan, step 6).

## 5. The decisions

All made with the owner on 2026-09-29.

- **D1 — The history is rewritten**, so the layout enters master once. The branch is Rudolf's and
  on `origin`, so S2 ends in a force-push, which the owner confirms when it is ready.
- **D2 — The layout of section 3**: `tests/protocol/tcp/{linux,packetdrill}/` in both repositories,
  `.pkt` files in `inet-gpl` and `.test` files in INET; everything else in `tests/packetdrill/`,
  generic at the top and TCP's in `tcp/`.
- **D3 — The hand-written suites are deleted**, and the SCTP scripts come later.
- **D4 — The defaults become data** in `tcp/scripts.yaml`; `set_sysctls.py` stays one file. An
  agent merges an upstream change into the YAML as easily as it re-copies a file.
- **D5 — INET's runner is `bin/inet_run_packetdrill`**, independent of TCP, with the id below
  `tests/protocol/`.
- **D6 — INET's RFC-based TCP tests move into `tests/protocol/tcp/rfc/`.**
- **D7 — TCP alone** (decided by the owner on 2026-09-29, as recommended). The guide
  (`doc/project/guide/derive-tests-from-a-standard.md`, step 6) puts every standards-derived test
  in `tests/protocol/<proto>/<Doc><Name>.test`, and ten other protocol folders follow it. Moving
  TCP alone makes TCP the exception, and the guide then states both forms. Recommendation: **TCP
  alone now**, because only TCP has other kinds of test beside the RFC ones; the guide says so, and
  a protocol moves to `rfc/` when a second kind of test arrives for it.
- **D8 — The plans stay in `inet-gpl`**, squashed by S2 into one commit without local paths.

## 6. The steps

**S1 — The layout. — done 2026-09-29.** Delete `tests/packetdrill/{sctp,tcp,udp}`. Move the scripts to
`tests/protocol/tcp/{linux,packetdrill}/` and everything else to `tests/packetdrill/`, with the
names of section 3. `linux-results.csv` replaces `golden/`: the Linux run writes it, `compare`
reads it, `verify-scripts` checks its sha256 column. Script ids become paths. The defaults become
the `defaults:` block, from which the Linux run writes each set's `defaults.sh` and the INET run
takes its sysctls; `known_preambles` goes (F9). The TCP half of `base.ini` and of the tool moves
into `tcp/`, without the keys that a preamble now states. **Done when** `make test` gives the
accepted baseline (296 / 0 / 7 / 12 / 3) from the new layout, `verify-scripts` is clean, the
mirrored folders hold nothing but `.pkt` files, and no file says *oracle*, *leg*, *gtests* or
*corpus* except where it quotes upstream.

Done on a local working branch, `topic/packetdrill-cleanup`, in eight steps: the hand-written
suites deleted, `linux-results.csv`, the layout, the defaults as data, the generic tool and `tcp/`,
the names, the wrappers at the scripts' paths, and the local paths and outside notes. Each step
gave the accepted baseline with the same verdict for each script, against INET `13eff5386e` of
#1155. S2 folds the steps into its series. Facts from the work:

- The tool's names: the runner `packetdrill_inet`; the commands `linux`, `inet`, `inet-one`,
  `compare`, `run`, `preprocess`, `verify-scripts`, `gen-wrappers`; the Makefile targets `inet`,
  `linux`, `report`, `test`, `verify-scripts`; the YAML key `script_sets`; the record fields
  `set`, `linux`, `inet`; the Makefile variable `PROTOCOL` (default `tcp`), which `suite.py` reads
  as `PACKETDRILL_PROTOCOL`.
- The defaults block changed one set's INET input: the packetdrill set gained the four settings
  of F9. No verdict changed.
- Eight keys of the old `base.ini` went instead of moving to `tcp.ini`: each preamble sets them on
  the command line, which beats the ini file.
- `gen-wrappers --into` is INET's `tests/protocol`. It writes only into the set folders, removes
  stale wrappers only there, and writes a `README.md` per set folder with the set's new `title`
  from `scripts.yaml`. The check for repeated names is gone (INET's runner changes in S4). The
  306 wrappers keep their expected results and feature lines: 158 in `tcp/linux/`, 148 in
  `tcp/packetdrill/`.

**S2 — The history. — done 2026-09-29.** In order: the deletion of the hand-written suites; the six `PacketDrillApp`
commits, commit 1 without its hunks in the deleted suite (F5); the use-after-free fix; one commit
that adds the scripts with their provenance and licence; one that adds the framework and
`linux-results.csv` under the final names; then `inet-one`, `gen-wrappers`, the feature map and
Linux's retransmission timer for the INET run; then one plan commit without local paths. Every
commit keeps its author. **Done when** every commit builds against the #1155 branch, and the head
tree equals the S1 tree plus S3.

The series on `inet-gpl` master `9b2fb1d`, 16 commits:

| # | Author | Commit |
| --- | --- | --- |
| 1 | Rudolf Hornig | packetdrill: make the app work for TCP, not only SCTP |
| 2 | Levente Meszaros | tests: delete the hand-written packetdrill suites |
| 3 | Rudolf Hornig | packetdrill: extend the script dialect to the TCP scripts of Linux |
| 4 | Rudolf Hornig | packetdrill: TCP connection model, event scheduling and socket plumbing |
| 5 | Rudolf Hornig | packetdrill: the syscall surface that the TCP scripts exercise |
| 6 | Rudolf Hornig | packetdrill: tcp_info bridge and %{ }% assertion blocks |
| 7 | Rudolf Hornig | packetdrill: live-connection injection and outbound comparison |
| 8 | Levente Meszaros | packetdrill: stop reading a freed queue element while emptying a list |
| 9 | Rudolf Hornig | tests/protocol/tcp: add the TCP packetdrill scripts of Linux and of packetdrill |
| 10 | Rudolf Hornig | tests/packetdrill: add the suite that runs the TCP scripts on Linux and in INET |
| 11 | Levente Meszaros | tests/packetdrill: add inet-one, the INET run of one script for a test runner |
| 12 | Levente Meszaros | tests/packetdrill: generate INET's wrapper test files for the scripts |
| 13 | Levente Meszaros | tests/packetdrill: name what each script exercises in INET's wrappers |
| 14 | Levente Meszaros | tests/packetdrill: select Linux's retransmission timer for the INET run |
| 15 | Levente Meszaros | tests/packetdrill: select Linux's initial window and ICMP reaction for INET |
| 16 | Levente Meszaros | plan: the cleanup of the packetdrill branch, and the INET wrappers |

What changed from the plan above, and how the series was made:

- Commit 1 comes before the deletion and keeps its hunks in the hand-written suite (F5, F10).
- The packet construction of commit 7 moved into commit 3 (F20), so that every commit builds.
- The comment corrections of S1 and S3, and the twelve "Workstream" labels (F18), are applied in
  each commit whose files hold the old text; commit 3 has the parser generated again (F17). No
  commit of the series names `oracle.py`, a leg, `mapping.yaml` or a work package.
- Commits 1 to 8 keep each author's tree, without the hand-written suite from commit 2 on. Commit
  9 takes `tests/protocol` of the S1 tree. Commits 10 to 15 take `tests/packetdrill` from the S1
  and S3 tree with the later changes removed: commit 10 has no `inet-one`, `gen-wrappers`,
  feature map or Linux keys of the last two commits, and each later commit adds its part back.
  The framework commit carries the whole S1 shape (the layout, the CSV, the defaults as data,
  the generic tool and `tcp/`, the names) under the author of the framework.
- Four texts of the S1 tree changed first so that they read the same with and without the later
  commits: the header of `linux-results.csv`, two docstrings, and the command in the source
  README.
- The author dates are those of the original commits; the scripts carry the date of the commit
  that copied them.

Checked against INET `359db08cc3` (F22), OMNeT++ 6.4.0, in debug mode:

- commits 1 to 8 each build (`make MODE=debug`, the packetdrill objects built again each time);
- the scoreboard of commits 10 to 13 is 222 MATCH, 81 DIVERGENCE, 12 KERNEL_DRIFT,
  3 UNSUPPORTED_FEATURE: #1155 makes INET's TCP follow the RFCs by default where Linux does not;
- commit 14 gives 226 MATCH and 77 DIVERGENCE, and commit 15 gives 297 MATCH, 6 DIVERGENCE, with
  the same verdict for each script as the S1 and S3 tree;
- at commit 11, `inet-one` gives the exit status of the INET run's verdict for all 318 scripts; at
  commit 12, `gen-wrappers` writes 306 wrappers and `--check` finds nothing out of date;
- the tree of commit 15 equals the S1 and S3 tree except the "Workstream" comments, and commit 16
  adds the plans.

The force-push replaced the 22 commits on `origin` on 2026-09-29, with the owner's confirmation.
The second session of F21 had finished before it; a session that works on the branch now uses the
new layout.

**S3 — The READMEs. — done 2026-09-29.** `tests/packetdrill/README.md` keeps what a reader needs from the three
outside documents -- the design in short, and the pitfalls the debugging session found -- and
drops the references (F6). `tcp/README.md` holds the scripts' provenance and licence, and today's
scoreboard with the seven divergences listed as known and open (F7). The two texts that name the
deleted suites follow the move (F8). **Done when** no README names a document outside the
repository or a folder that no longer exists.

The two outside notes that name the pitfalls, the debugging session and the recon report, are not
on this machine; the pitfalls come from the commit messages of the branch and the gotchas of the
implementation plan. The source README also got a new Usage section (its example named the
deleted suite's network and files) and corrected Limitations (`%{ }%` blocks, blocking calls and
`getsockopt()` work now).

**S4 — INET follows. — done 2026-09-29.** On the INET branch, rebased onto the rebased #1155 branch:

- move the 27 RFC-based TCP tests and `TcpMutations.h` into `tests/protocol/tcp/rfc/` with
  `git mv` alone, in a commit of its own, and update the four evidence documents under
  `doc/project/evidence/model/tcp/` that name the test paths, and the guide per D7; the finished
  plans under `plan/done/` keep the paths they had;
- regenerate the wrappers into `tests/protocol/tcp/{linux,packetdrill}/` with their subfolders and
  the ids below `tests/protocol/`;
- replace `tests/protocol/tcp/packetdrill/run` with `bin/inet_run_packetdrill`;
- change INET's test runner to extract each test beside it;
- update the INET plan.

**Done when** the 27 RFC tests give the same verdicts from `rfc/` as from `tcp/`; INET's runner
gives 296 PASS, 3 FAIL (expected), 7 FAIL (unexpected) for the wrappers again; the two
`Fragmentation.test` no longer share a folder; and `opp_repl` gives the same.

The RFC-test move depends neither on packetdrill nor on #1155, so it can also go to INET master on
its own, first.

Done on `topic/tcp-packetdrill-tests`, on INET `359db08cc3`, in eight commits; the INET plan
(`plan/pending/packetdrill-tcp-protocol-tests.md` there) records them. What differs from the
list above:

- **INET's runner extracts only a `%testprog` test beside its `.test` file.** The wifi tests
  include `../../ini/_b.ini` relative to `work/<file name>` of their test folder, and all 45 of
  them that pass fail from a folder beside the test. A `%testprog` test builds nothing and has no
  such path, and the wrappers are exactly those tests. The runner also puts the test's own folder
  on the include path, which `TcpMutations.h` in `rfc/` needs.
- **The `Fragmentation.test` clash no longer exists** on this base: `ipv4/Fragmentation.test` is
  gone. The only repeated name among the other protocol tests is `Rfc1122ChecksumDiscard.test`, in
  two test folders, which never share a work folder.
- **The evidence documents do not change.** They name the tests by file name only; their run
  records keep the command of their time.
- **The classification gate did not know `bin/`**, so a commit that touched only
  `bin/inet_run_packetdrill` failed with any area; a commit of the step repairs the gate.
- **The wrappers move in two commits**, a pure move and then the new content, because the commit
  gate refuses a rename together with a content change.

Checked: the 27 RFC tests give 25 PASS and 2 FAIL (expected) from `rfc/`, as from `tcp/`; the 306
wrappers give 297 PASS, 3 FAIL (expected) and 6 FAIL (unexpected) (six, not seven: F22); all 588
protocol tests give 537 PASS, 45 FAIL (expected) and the six. `opp_repl` gives the wrappers the same
results, but cannot build the other protocol tests (269 ERROR, `ProtocolTest.h` not found): it does
not add `tests/protocol/lib`, an older gap of `opp_repl`. `opp_repl` `bb4d294` repaired it the same
day: it runs INET's protocol tests as suites with the shared library, and gives each of the 588
tests the result of INET's runner. INET's runner and `opp_repl` also select a subfolder of a suite
with `-w` now, such as `-w tests/protocol/tcp/rfc`.

**S5 — Verification.** `inet-gpl`'s fingerprints and statistical results against INET with #1155:
each moved row re-recorded and explained (F13).

**S6 — The merge. — done 2026-09-29, earlier than planned.** After #1155 merges into INET master:
rebase onto `inet-gpl` master, run S5 once more, merge, and push. The companion plan's INET steps
follow.

The owner merged the branch before both conditions: `master` was still at `9b2fb1d`, so no rebase
was needed, and `master` moved to the branch by a fast-forward. **Since then, `inet-gpl` master
builds only against INET #1155** (`topic/tcp-new-audit-fixes`, checked at `359db08cc3`): F1
holds for master now. Before the merge it built against neither INET master nor #1155 (F10).
S5 is still open: `inet-gpl`'s own fingerprints and statistical results against #1155 (F13).

## 7. Effort

S1 and S3 are half a day together: the moves are mechanical, and the Linux run's temporary tree is
the one new piece. S4 is a few hours. S2 is a history rewrite of 21 commits with a build of each,
about a day. S5's baseline part is the long one: the row explanations take the time, not the runs.
