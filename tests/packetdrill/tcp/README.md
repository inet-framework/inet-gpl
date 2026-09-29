# The TCP scripts

This folder holds what is TCP's in the packetdrill suite: the configuration of the TCP scripts,
the results of the Linux run, and the TCP rules of the tool. [../README.md](../README.md) tells
how the suite runs a script.

## The two sets

The scripts are copies of two upstream repositories, in `tests/protocol/tcp/`:

| Set | Folder | Scripts | Upstream | Commit | Pinned | Copied from |
| --- | --- | --- | --- | --- | --- | --- |
| `linux` | `tests/protocol/tcp/linux/` | 159, flat | https://github.com/torvalds/linux.git | `d96fcfe1b7f94ac742984ae7986b94a116abff1b` | 2026-07-10 | `tools/testing/selftests/net/packetdrill/` |
| `packetdrill` | `tests/protocol/tcp/packetdrill/` | 162, in 31 feature folders | https://github.com/google/packetdrill.git | `2c4001c4d6fc04a3bbd01d4b92be62717a37648a` | 2026-03-11 | `gtests/net/tcp/` |

The two folders hold nothing but the `.pkt` files, copied **verbatim**. `linux-results.csv`
records the sha256 of each script that the Linux run ran, and `make verify-scripts` hashes each
script again. A copy with other line endings or other formatting fails that check.

These upstream files are not copied:

- the helpers that the scripts call: the three `defaults.sh` files are data, and are now the
  `defaults:` block of `scripts.yaml`; the two copies of `set_sysctls.py` are one file here;
- the kselftest files of the Linux set (`ksft_runner.sh`, `config`, `Makefile`), and
  `ts_recent/randomization_test.sh` of the packetdrill set, because no script uses them;
- the other folders of `gtests/net/` (`packetdrill/`, `psp/` and other items), which are not TCP.

## Licence

The scripts keep their upstream licence, GPL-2.0:

- the Linux set: 101 of the 159 scripts have `SPDX-License-Identifier: GPL-2.0`, and the kernel's
  `COPYING` covers the others;
- the packetdrill set: the repository's `LICENSE` is GPL-2.0, and the scripts have no header.
  `set_sysctls.py` has Google's copyright header.

The scripts are input files of the suite, and no program of this repository includes them.
INET's wrappers hold the id of a script, but no line of it.

## The files

| File | What it holds |
| --- | --- |
| `scripts.yaml` | the upstream pin of each set, the helpers that the Linux run places around the scripts, the `defaults:` block, the environment of the Linux run, the skips, and the kernel drift |
| `linux-results.csv` | the Linux run on the pinned kernel: the verdict and the sha256 of each script, and a header with the kernel release, the packetdrill commit and the date |
| `sysctls.yaml` | the translation of Linux sysctls and socket options into the parameters of INET's `Tcp` |
| `tcp.ini` | the Linux behavior that no preamble states, as INET parameters; loaded after `../ini/base.ini` |
| `tcp.py` | the TCP rules of the tool; its docstring names what a protocol module must give |
| `set_sysctls.py` | Google's helper, which the Linux run places where the scripts expect it |

## The defaults

All 321 scripts load a `defaults.sh` by a relative path. Upstream has two variants. They set 21
sysctls the same way, and differ in `tcp_fastopen` (`0x3` for the Linux set, `0x70403` for the
packetdrill set) and `tcp_ecn_option` (only the packetdrill set sets it). The `defaults:` block of
`scripts.yaml` holds both, and both runs read it:

- the Linux run writes a `defaults.sh` for each set from it into its copy of the scripts;
- the INET run translates its sysctls through `sysctls.yaml`.

`kernel:` in the same block holds the Linux defaults that no preamble sets, but that the INET run
must copy, for example `tcp_window_scaling`.

The scripts reach the helpers by relative paths in three folders, and the Linux run places the
helpers in the same folders of its copy (`helpers:` in `scripts.yaml`):

| Folder of the helpers | Scripts that use it | In upstream |
| --- | --- | --- |
| the set folder: `defaults.sh`, `set_sysctls.py` | the Linux set, as `./defaults.sh` | `tools/testing/selftests/net/packetdrill/` |
| `common/` in the set folder: `defaults.sh`, `set_sysctls.py` | the packetdrill set, as `../common/` or `../../common/` by folder depth | `gtests/net/tcp/common/` |
| `common/` above the set folder: `defaults.sh` | 29 scripts of the packetdrill set, as `../../common/` or `../../../common/` by folder depth | `gtests/net/common/`, a copy of the packetdrill variant |

## The TCP rules

`tcp.py` holds what the generic tool must know about TCP:

- the flags of the Linux run and the `-D` symbols of the scripts;
- `tcp_cubic`'s module parameter folder, which the privileged run saves and restores;
- the sysctls that are not a plain entry of `sysctls.yaml`: `tcp_rmem`, the MTU of the tun
  interface, the attributes of a route;
- the changes for one script in the INET run: the Fast Open listener, a `tc qdisc` in the
  preamble, the scripts that read explicitly;
- the category of a script, and the kernel source file to read when a script diverges.

Two choices of the comparison are TCP's, and are in `PacketDrillApp`:

- **The TCP window field is not compared.** INET's receive window does not follow the
  autotuning of Linux byte for byte.
- **A GSO super-segment matches several segments.** Linux sends one large segment where INET
  sends segments of MSS size. The comparison adds up the segments that follow in sequence, until
  their payload is the size of the expected segment.

**The congestion control is INET's `TcpCubic`**, because the defaults set
`tcp_congestion_control` to `cubic`. `sysctls.yaml` translates the other algorithms that INET
has. An algorithm that INET does not have, for example `bbr`, goes into `unmapped_knobs`, and
INET then uses its own default.

## The privileged scripts

Five scripts cannot run under the fake root of `unshare -r`. Run them with
`make linux PRIVILEGED=1`:

| Scripts | They need |
| --- | --- |
| `tcp/packetdrill/cubic/cubic-hystart-delay-rtt-jumps-upward`, `tcp/packetdrill/cubic/cubic-hystart-delay-min-rtt-jumps-downward` | to write `/sys/module/tcp_cubic/parameters/hystart_detect`; module parameters belong to root and are not in a namespace |
| `tcp/packetdrill/fastopen/client/fallback-exp-opt`, `tcp/packetdrill/fastopen/client/nonblocking-sendto` | `ip tcp_metrics flush all`, which checks `CAP_NET_ADMIN` in the **initial** user namespace |
| `tcp/linux/tcp_rcv_wnd_shrink_nomem` | a locked read buffer of 2 MB; `packetdrill` calls `mlockall()`, and a user without privilege cannot lift the hard limit of `RLIMIT_MEMLOCK` |

## The scoreboard

Measured on 2026-09-29: Linux 7.1.3, INET `359db08cc3` of the #1155 branch in debug mode,
OMNeT++ 6.4.0.

| Verdict | Scripts |
| --- | --- |
| `MATCH` | 297 |
| `DIVERGENCE` | 6 |
| `KERNEL_DRIFT` | 12 |
| `UNSUPPORTED_FEATURE` | 3 |
| `CRASH`, `DIALECT_GAP`, `LINUX_SUSPECT` | 0 |
| skipped | 3 |

**The six divergences are known and open.** They are four scenarios; two scripts are in both
sets:

| Script | What INET does |
| --- | --- |
| `tcp/linux/tcp_slow_start_slow-start-after-win-update`, `tcp/packetdrill/slow_start/slow-start-after-win-update` | a packet at the wrong time, at 5.8 s; the script also sets `tcp_min_tso_segs`, which INET does not translate |
| `tcp/linux/tcp_tcp_info_tcp-info-rwnd-limited`, `tcp/packetdrill/tcp_info/tcp-info-rwnd-limited` | stops at event 15 of 22: an expected packet does not come |
| `tcp/packetdrill/cubic/cubic-rto-ss-ca-cwnd-bump` | a packet at the wrong time, at 2.504 s |
| `tcp/packetdrill/fast_retransmit/fr-4pkt-fack-last-byte` | the tail loss probe goes out at 2.802 s; the script expects it at 2.202 s |

A run in July 2026 recorded 303 MATCH and no divergence. INET's `topic/tcp-new` and the later
commits of #1155 gave seven divergences, and each INET parameter that the run sets exists. Nobody
has found the INET and OMNeT++ state of the July run. The seventh,
`tcp/packetdrill/shutdown/shutdown-rdwr-send-queue-ack-close`, passes since INET `f3ab035caa`.

**The three unsupported scripts** change a `tc qdisc` in the middle of the run, to drop packets
by local congestion. INET does not model this: `tcp/linux/tcp_user_timeout_user-timeout-probe`,
`tcp/packetdrill/user_timeout/user-timeout-probe` and
`tcp/packetdrill/cubic/cubic-rack-reo-timeout-retrans-failed-incoming-data`.

**The kernel drift and the skips** are in `scripts.yaml`, each with its reason. The skipped
scripts need IPv6.

## Copy the scripts again after a new pin

Get the two upstream repositories at the commits that you want to pin. From the root of
inet-gpl, copy the scripts:

```sh
K=<linux-clone>/tools/testing/selftests/net/packetdrill
G=<packetdrill-clone>/gtests/net/tcp
rm tests/protocol/tcp/linux/*.pkt && cp -p $K/*.pkt tests/protocol/tcp/linux/
rsync -a --delete --prune-empty-dirs --include='*/' --include='*.pkt' --exclude='*' \
    $G/ tests/protocol/tcp/packetdrill/
```

Then do these steps:

1. Compare upstream's `defaults.sh` files and `set_sysctls.py` at the old and the new commit.
   Apply the changes to the `defaults:` block of `scripts.yaml` and to `set_sysctls.py`.
2. Set `git_commit` and `pinned_date` of the set in `scripts.yaml`.
3. Record the Linux results again, as [../README.md](../README.md#record-the-linux-results-again)
   tells.

`make verify-scripts` fails between the copy and the new Linux results. That is correct: the check
finds scripts that moved without their Linux results.
