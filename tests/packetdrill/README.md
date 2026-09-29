# The packetdrill suite

This folder holds the tool that runs packetdrill scripts against INET and against the real Linux
kernel, and compares the two results. A script states what a TCP stack must do, packet by packet
and system call by system call. If Linux and INET both pass a script, INET does what Linux does.

The suite runs each script twice:

- **The Linux run** gives the script to upstream `packetdrill`, which runs it against the kernel of
  the machine, in a new network namespace. The run records its result in the protocol's
  `linux-results.csv`, which is in git.
- **The INET run** gives the script to INET's `PacketDrillApp`, in a simulation. The run records its
  results in `out/inet_results/`.

`compare` joins the two results into a scoreboard, `out/report.md` and `out/report.json`.

The scripts are not in this folder. They are in `tests/protocol/<protocol>/<set>/`, in the same
tree as INET's protocol tests. A script's id is its path below `tests/protocol/`, without `.pkt`:
`tcp/packetdrill/fast_retransmit/fr-4pkt-sack`. INET has a wrapper `.test` file with the same path,
which runs the script through `inet-one` (see [INET's wrappers](#inets-wrappers)).

## The files

| File | What it holds |
| --- | --- |
| `suite.py` | the tool: the two runs, the translation of a script's preamble, the comparison, the wrapper generator |
| `Makefile` | the targets that a developer uses; `make help` lists them |
| `ini/base.ini` | the simulation that every protocol shares: the host, the tun interface, the capture, the timing tolerance |
| `ned/PacketDrillNetwork.ned`, `ned/pdhost.mrt` | the network: one `PacketDrillHost` and its routes |
| `tcp/` | what is TCP's: the configuration of the scripts, the Linux results, the translation tables, the TCP rules of the tool; see [tcp/README.md](tcp/README.md) |

`PROTOCOL=tcp`, the default, selects the protocol folder. `suite.py` loads the folder's
`<protocol>.py` for the protocol's rules, and gives `<protocol>.ini` to the simulation after
`base.ini`.

## Set up the environment

Source both environments in every shell, in this order. Go to each root folder first, because
each `setenv` script uses the current folder and not its own folder:

```sh
cd <inet> && source setenv -q
cd <inet-gpl> && source setenv -q
```

The INET run uses the **debug** libraries of both projects. Build them, and build them again
after each C++ change:

```sh
cd $INET_ROOT && make MODE=debug -j$(nproc)
cd $INETGPL_ROOT && make MODE=debug -j$(nproc)
```

`suite.py` needs PyYAML. The `python3` on the `PATH` does not always have it. If it does not, give
`PYTHON=<interpreter>` to `make`. `make check-env` shows the interpreter, the runner and the tools
that it finds, and runs nothing.

## Run the suite

Run the targets from this folder. The first run builds the runner, `packetdrill_inet_dbg`.

```sh
make                        # the INET run over all scripts
make test                   # the INET run, then the scoreboard
make summary                # the headline of the last scoreboard
make inet FILTER=fastopen   # FILTER is a regex over the script id
make linux                  # the Linux run: RE-RECORDS linux-results.csv
make verify-scripts         # the scripts against the sha256 in linux-results.csv
make build                  # the runner, after a C++ change (rebuild: from scratch)
make help                   # all targets and variables
```

The INET run of all scripts takes about 90 seconds. The default target does not do the Linux run,
because the Linux run changes a file in git and needs `/dev/net/tun`. The Linux results change
only with the kernel, the scripts or their defaults, not with INET, so `make test` is the usual
loop.

`suite.py` has the same commands, and some more:

```sh
python3 suite.py linux [--filter REGEX] [--tolerance-usecs N] [--privileged]
python3 suite.py inet [--filter REGEX]
python3 suite.py inet-one <id>             # one script, as a test runner calls it
python3 suite.py compare [--filter REGEX]
python3 suite.py run [--filter REGEX]      # linux, inet and compare
python3 suite.py preprocess [--filter REGEX] [--verbose]   # the translation only
python3 suite.py verify-scripts [--filter REGEX]
python3 suite.py gen-wrappers --into <inet>/tests/protocol [--check]
```

## How a script runs

**The Linux run** copies the scripts into a temporary tree of upstream's shape, because the
scripts load their preamble through relative paths such as `../common/defaults.sh`. The
protocol's `scripts.yaml` gives the helper files of each set: the tool writes `defaults.sh` from
the `defaults:` block, and copies the other helpers. `verify-scripts` checks that each relative
path in a script finds a file. Then `packetdrill` runs in `unshare -r -n` with `ulimit -s 2048`,
and needs no privilege.

**The INET run** does not execute the preamble. The tool removes the untimed backtick blocks from
the script, and takes the sysctls from the set's `defaults:` block and from the script's own
`sysctl` and `set_sysctls.py` calls. The protocol's `sysctls.yaml` translates each sysctl and
socket option into an INET parameter, which goes to the simulation on the command line. A setting
without a translation goes into the record as `unmapped_knobs`. If a script needs a setting that
INET cannot model, the verdict is `INET_UNSUPPORTED_CONFIG`, and the simulation does not start.

**The comparison** takes the verdict of each run and gives one combined verdict:

| Verdict | Meaning | What to do |
| --- | --- | --- |
| `MATCH` | Linux and INET both pass the script | nothing |
| `DIVERGENCE` | Linux passes; INET sends a different packet, sends it at a different time, or stops before the end (`INET_STALLED`) | repair INET; read the record's `divergence` and `kernel_source_hint` |
| `UNSUPPORTED_FEATURE` | the script needs a setting that INET does not model | add the feature to INET, or leave the script unsupported |
| `DIALECT_GAP` | `PacketDrillApp` cannot parse the script | extend the parser; `report.md` groups the gaps by construct |
| `CRASH` | the simulation stops with an error that is not a packetdrill assertion | repair the crash; read the record's `diagnostic` |
| `KERNEL_DRIFT` | Linux fails the script, and the reason is known: this kernel does not do what the script states | nothing; the protocol's `scripts.yaml` gives the reason for each script |
| `LINUX_SUSPECT` | Linux fails the script, and nobody knows why yet | examine the Linux run; until now each case was a problem of the environment, not of the kernel |

A record in `report.json` also holds `stripped_preamble` (the settings that the tool took from the
preamble), `ini_overrides` (the INET parameters that it set) and `unmapped_knobs`.

## The privileged Linux run

Some scripts cannot run under the fake root of `unshare -r`. For TCP there are five, and
[tcp/README.md](tcp/README.md) names them. `make linux PRIVILEGED=1` runs `packetdrill` with
`sudo -n unshare -n`: real root, the same network namespace. The run also lifts `RLIMIT_MEMLOCK`.

Run `make` as yourself, not with `sudo make`. Only the `packetdrill` command runs as root. With
`sudo make`, `linux-results.csv` becomes root's file, and sudo's `PATH` finds a different
`python3`. The run needs `sudo` without a password for `unshare`. If your policy needs a
password, refresh the sudo timestamp first:

```sh
sudo -v && make linux PRIVILEGED=1 FILTER=cubic-hystart
```

Module parameters are not in a namespace, and the scripts do not restore what they write. The
protocol's rules name the parameter folders that the privileged run saves before the run and
restores after it.

## Record the Linux results again

Do this after a kernel upgrade, or after a new copy of the scripts:

1. Run `make linux`, and `make linux PRIVILEGED=1` for the scripts that need it. The run writes
   `linux-results.csv` again, with the kernel release and the date in its header.
2. Run `make verify-scripts`. It must be clean.
3. Run `make test`, and examine each verdict that changed. A script that Linux no longer passes
   is `LINUX_SUSPECT` until its reason goes into `kernel_drift` in the protocol's `scripts.yaml`.
4. Commit `linux-results.csv` and `scripts.yaml`. Git keeps the old results.

## INET's wrappers

INET's protocol tests run the scripts through wrapper `.test` files, one for each script that
Linux passes and that the suite runs. A wrapper holds the script's id, its origin, what it
exercises and its expected result, but no line of the script. The scripts are GPL-2.0 and stay
in this repository.

A wrapper calls INET's `inet_run_packetdrill <id>`, which calls `suite.py inet-one <id>`.
`inet-one` does the same preparation and classification as `inet`, prints the simulation output,
and then one line:

```
PACKETDRILL tcp/packetdrill/fast_retransmit/fr-4pkt-sack: PASS
PACKETDRILL tcp/packetdrill/fast_retransmit/fr-4pkt-sack: FAIL (INET_DIVERGE: <detail>)
```

It exits with 0 only on a pass, and with 2 for an unknown id. For a script that the suite skips,
it prints `#SKIPPED: <reason>`, which `opp_test` counts as a skip. It writes nothing into
`out/inet_results/`, and each run writes its own capture file, so parallel runs do not collide.

`gen-wrappers --into <inet>/tests/protocol` writes the wrappers at the scripts' own paths, and a
`README.md` in each set folder that lists the scripts without a wrapper. It changes only the set
folders. A wrapper expects `FAIL` if the INET run cannot run its script, and `PASS` if it can.
`--check` compares and writes nothing, and exits with 1 if a file is out of date.

## Pitfalls

Each of these cost time once.

- **A pass must be a pass to the end.** `PacketDrillApp` does not stop the simulation; every run
  stops at the time limit. The tool classifies a run from its output, not from the exit status.
  The observation window closes when the script has no more events and every expected packet has
  arrived, as upstream `packetdrill` stops at the last line of the script. Without this, the
  retransmissions and delayed ACKs after the script show as unexpected packets.
- **Do not give an option on the command line that the script sets itself.** `packetdrill` reads
  the script's own option lines first and the command line second, so the command line wins. The
  Fast Open scripts set their own IP addresses, because a cookie depends on them; a forced
  address gave all seven the same wrong cookie. The Linux run leaves out each option that the
  script sets.
- **Keep `ulimit -s 2048` in the Linux run**, in both modes. `packetdrill` calls `mlockall()`,
  which fails under the 8 MB memlock limit of a user namespace with the default stack size. The
  stack size also changes the result of `eor/no-coalesce-retrans`.
- **`nstat` gets a private history file.** Its default file name comes from `getuid()`, which is
  0 in both modes, so a privileged run could not open the file of an unprivileged run.
- **`ethtool` must be on the `PATH` for the Linux run.** Some scripts switch off the offloads of
  the tun interface with it. Without it, the kernel joins segments that the script expects apart,
  and the script fails later on a payload size, not on the missing tool. `make check-env` shows
  it.
- **In the ini files, the first match wins.** `base.ini` and `<protocol>.ini` load together, each
  with its own `[General]`, so a key must be in one file only. A value on the command line wins
  over both files, so an ini key that a preamble also sets does nothing.
- **"Packet arrived at the wrong time" is about time, not about the packet.** Examine the timers
  first. The tolerance of the comparison is the `latency` of the tun application in `base.ini`.
- **A timed `sysctl` changes only the settings that `PacketDrillApp::runCommandEvent()` knows.**
  It changes the INET parameter, and connections that open after it use the new value, as on
  Linux. The application logs and ignores all other settings, so a script that changes another
  setting in the middle of the run can diverge.
- **A result that changes between machines can be a memory error.** Six loops in `PacketDrill`
  removed the queue element that their iterator pointed to, and 100 scripts crashed with one
  allocator and passed with another. Run a crash under valgrind before you look for a protocol
  cause.
- **The Makefile runs one target at a time (`.NOTPARALLEL`).** `report` reads what `inet` writes.
  Some shells export `MAKEFLAGS=-j`, and a parallel `make test` then scores the previous run.

## Limits

- **IPv4 only.** The tool gives fixed IPv4 flags; the protocol's `scripts.yaml` skips each script
  that needs IPv6.
- **A divergence message is short** ("Datagrams are not the same"). The last lines of the record's
  `context_log` usually show the two packets. `context_log` also holds the color codes of the
  simulation output.
