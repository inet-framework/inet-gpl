# TCP oracle test framework

Differential testing for INET's TCP against the real Linux kernel: the same
packetdrill script runs under both **leg L** (upstream `packetdrill` against
the live kernel) and **leg I** (INET's `PacketDrillApp`), and the results are
compared into a scoreboard showing where INET's TCP matches Linux, where it
diverges, and where it can't run a script at all.

Background and design rationale: see the implementation plan at
`~/w/ai/ai-plans/plans/pending/inet-2026-07-11_tcp-linux-oracle-test-framework.md`
and the feasibility recon at `~/w/ai/packetdrill-oracle/RECON-REPORT.md`.
`~/w/ai/packetdrill-oracle/DEBUGGING-SESSION-2026-07-11.md` documents seven
structural bugs found and fixed in `PacketDrillApp`/`PacketDrill.cc` while
bringing the leg-I runner up — required reading before touching that code.

## Environment setup

Every shell needs both INET and INETGPL environments sourced, **in this
order, by `cd`-ing into each root first** (their `setenv` scripts use `pwd`,
not their own script directory, so `source /path/to/setenv` from elsewhere
silently mis-sets the root variable):

```sh
cd $INET_ROOT && source setenv -q
cd $INETGPL_ROOT && source setenv -q
```

Both repos need **debug** builds (leg I always runs the debug library):

```sh
cd $INET_ROOT && make MODE=debug -j$(nproc)
cd $INETGPL_ROOT && make MODE=debug -j$(nproc)
```

The oracle framework's own small test executable needs building once (and
after any C++ change to `PacketDrillApp`/`PacketDrill`):

```sh
cd $INETGPL_ROOT/tests/oracle/build
opp_makemake -f --deep -lINET_dbg -lINETGPL_dbg \
  -L$INET_ROOT/src -L$INETGPL_ROOT/src -P . \
  -I$INET_ROOT/src -I$INETGPL_ROOT/src -o oracle_exe
make MODE=debug
```

## Running

All commands assume `cwd = $INETGPL_ROOT/tests/oracle`.

```sh
python3 oracle.py linux [--filter REGEX] [--tolerance-usecs N]   # leg L: real kernel -> golden/
python3 oracle.py inet [--filter REGEX]                          # leg I: INET -> out/inet_results/
python3 oracle.py compare [--filter REGEX]                       # join -> out/report.json, out/report.md
python3 oracle.py run [--filter REGEX]                            # linux + inet + compare in sequence
python3 oracle.py preprocess [--filter REGEX] [--verbose]        # dry-run the sysctl/option mapping, no execution
```

`--filter` is a regex matched against `"<corpus>:<script_id>"`, e.g.
`--filter 'kernel:tcp_close_'` or `--filter 'gtests:fast_retransmit/'`.

Leg L (`linux`) requires no privileges — it runs packetdrill inside
`unshare -r -n` (see `run_leg_linux()` in `oracle.py` for the exact recipe
and why `ulimit -s 2048` is mandatory). Leg I (`inet`) requires the double
`setenv` above to be sourced in the same shell (`oracle.py` checks and exits
with a clear message if not).

Since leg L only depends on the pinned corpus and the running kernel, it does
not need re-running every time INET/INETGPL changes — only `inet` and
`compare` do. `run` re-runs all three; for iterating on INET fixes, prefer
`inet` + `compare` alone.

## Re-recording goldens after a kernel upgrade

Golden results are keyed by `environment.kernel_release` in `corpus.yaml`
(`golden/<kernel_release>/`). After upgrading the kernel:

1. Update `kernel_release` (and `packetdrill_binary` if it moved) in
   `corpus.yaml`.
2. `python3 oracle.py linux` to populate the new `golden/<new_release>/`
   directory. The old one is left in place (harmless; `compare` only reads
   the directory matching the current `kernel_release`).
3. Commit the new `golden/` directory. Consider whether the old one is still
   worth keeping (e.g. for historical comparison) or should be deleted.

Corpus re-pins (`corpora.*.git_commit` in `corpus.yaml`) follow the same
pattern: update the pin, re-run `linux` (the script set may have changed),
then `inet` + `compare`.

## Reading the scoreboard

`out/report.md` is the human-readable summary; `out/report.json` is the
machine-readable array an agent should consume. Each record's
`combined_verdict` is one of:

| Verdict | Meaning | What an agent should do |
|---|---|---|
| `MATCH` | Both legs agree the script's contract holds | Nothing — this protocol behavior is verified correct |
| `DIVERGENCE` | Leg L passed, leg I disagreed on the wire | **Fix INET's TCP** — read `leg_i.divergence`, `kernel_source_hint` |
| `UNSUPPORTED_FEATURE` | The script needs a sysctl/option with no INET equivalent | **Implement the feature** in INET's TCP (see `mapping.yaml`'s `sysctl`/`option` maps for what's missing) |
| `DIALECT_GAP` | INET's packetdrill parser can't read the script at all | **Extend the parser** (`PacketDrill.cc`/lexer/grammar) — see the dialect-gap clustering in `report.md` for which construct blocks the most scripts |
| `CRASH` | INET's leg threw an unexpected error (not a packetdrill assertion) | **Fix the crash** — often a real bug, sometimes a framework/port gap; read `diagnostic` |
| `ORACLE_SUSPECT` | Leg L itself failed/errored or has no golden result | Not INET's fault — investigate the kernel-side result before trusting anything else about this script |

Per-script JSON records also carry `stripped_preamble` (the script's parsed
sysctl/option preamble), `ini_overrides` (what got translated into INET
config), and `unmapped_knobs` (sysctls/options with no mapping — attribution
hints for `DIVERGENCE`/`UNSUPPORTED_FEATURE`, most commonly
`net.ipv4.tcp_congestion_control=cubic`, since INET has no CUBIC flavour).

## Known limitations (as of the 2026-07-11 baseline)

- **IPv4 only.** Two corpus scripts that force `--ip_version=ipv6` are
  skipped (`corpus.yaml`'s `skips`); no IPv6 support is planned for phase 1.
- **`context_log` carries raw ANSI color codes** from Cmdenv's colorized
  output — fine for JSON/grep, noisy if pasted directly; consider stripping
  before display.
- **Divergence messages are coarse** ("Datagrams are not the same") without
  a field-level diff — `context_log`'s last ~30 lines usually contain the
  actual packet dump, but extracting a clean "expected X, got Y" line
  automatically hasn't been built.
- **`accept()`/passive-open connection ID**: the fix for `tcpConnId` (see
  the debugging session doc, fix #6) only covers the active-open (`connect()`)
  path. Passive-open scripts passed in the legacy 10-test suite without an
  equivalent fix, but this hasn't been specifically stress-tested against a
  `close()`-immediately-after-`accept()` script at corpus scale.
- **No pcap capture.** Not needed in the end — INET's own internal
  comparator, once actually wired up (see the debugging session doc), is the
  comparison mechanism. A `PcapRecorder`-based Python-side comparator was
  scoped and then found unnecessary.
- **No congestion-control equivalence.** `net.ipv4.tcp_congestion_control`
  is deliberately left unmapped (INET has no CUBIC/BBR/etc. flavours) rather
  than blocking every script that inherits `cubic` from `defaults.sh` — see
  `mapping.yaml`'s extensive comment on this design choice. Expect it to be
  the single most common `unmapped_knobs` entry across the whole corpus.
