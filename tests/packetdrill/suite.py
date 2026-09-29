#!/usr/bin/env python3
"""Run packetdrill scripts twice -- on the real Linux kernel (the Linux run) and in
INET's PacketDrillApp (the INET run) -- and compare.

The scripts live in tests/protocol/<protocol>/, and a script's id is its path
below tests/protocol/, e.g. tcp/linux/tcp_basic_client. See README.md for usage.
Single entry point; subcommands below.
"""
import argparse
import collections
import csv
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import yaml
except ModuleNotFoundError:
    # Whichever python3 wins on PATH is not necessarily the one PyYAML is
    # installed for -- omnetpp's nix dev shell ships a python3 without it while
    # the .venv beside it has it, and sudo's secure_path resolves a third one.
    # Point at a working interpreter rather than guessing which case this is.
    _candidates = []
    for _d in os.environ.get("PATH", "").split(os.pathsep):
        for _n in ("python3", "python"):
            _p = os.path.join(_d, _n)
            if os.access(_p, os.X_OK) and _p not in _candidates:
                _candidates.append(_p)
    _working = [
        _p for _p in _candidates
        if subprocess.run([_p, "-c", "import yaml"], capture_output=True).returncode == 0
    ]
    _hint = (f"  This one can:  make ... PYTHON={_working[0]}\n" if _working else
             "  No python3 on PATH can import it either -- install PyYAML, e.g. on NixOS\n"
             "  `nix-shell -p 'python3.withPackages(ps: [ps.pyyaml])'`, and pass that\n"
             "  interpreter as PYTHON=<path> (a dev shell's own python3 may shadow it).\n")
    sys.exit(f"PyYAML is not importable by {sys.executable}\n" + _hint +
             "  `make check-env` reports this before a run starts.")

SUITE_DIR = os.path.dirname(os.path.abspath(__file__))
INETGPL_ROOT = os.path.dirname(os.path.dirname(SUITE_DIR))
# The protocol whose scripts run: its folder holds the configuration, the Linux results and
# <protocol>.py, the rules that are the protocol's own (see the docstring there).
PROTOCOL = os.environ.get("PACKETDRILL_PROTOCOL", "tcp")
PROTOCOL_DIR = os.path.join(SUITE_DIR, PROTOCOL)
# The scripts, in INET's structure: a script's id is its path below this folder.
SCRIPTS_ROOT = os.path.join(INETGPL_ROOT, "tests", "protocol")


def _load_protocol_rules():
    import importlib.util
    spec = importlib.util.spec_from_file_location("packetdrill_" + PROTOCOL,
                                                  os.path.join(PROTOCOL_DIR, PROTOCOL + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROTOCOL_RULES = _load_protocol_rules()


DEFAULT_TOLERANCE_USECS = "50000"
LINUX_RUN_TIMEOUT_S = 60

BUILD_DIR = os.path.join(SUITE_DIR, "build")
BUILD_CMD = "make -C tests/packetdrill build"


def runner_path():
    """Path to the executable of the INET run.

    opp_makemake names the output directory after the toolchain
    (out/clang-debug, out/gcc-debug, ...), so discover it rather than
    hardcoding one. When several debug builds exist, clang wins; when none
    does, the conventional path is returned so error messages stay concrete.
    """
    found = sorted(glob.glob(os.path.join(BUILD_DIR, "out", "*-debug", "packetdrill_inet_dbg")))
    for path in found:
        if os.sep + "clang-debug" + os.sep in path:
            return path
    return found[0] if found else os.path.join(BUILD_DIR, "out", "clang-debug", "packetdrill_inet_dbg")


INET_RUN_TIMEOUT_S = 30
# PacketDrillApp never calls endSimulation() itself (PacketDrillApp.cc has no
# call site), so every run stops at this configured limit, not because the
# event queue becomes empty. This is NORMAL, not a hang signal;
# see classify_inet_output(). Because OMNeT++ is discrete-event, jumping
# straight to a far-future "check the limit" self-message costs no real
# wall-clock time regardless of magnitude (verified empirically), so this can
# be generous -- it only needs to exceed any real script's scripted duration.
INET_RUN_SIM_TIME_LIMIT = "300s"


def _live_commit(root_env_var):
    try:
        r = subprocess.run(["git", "-C", os.environ[root_env_var], "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def resolve_path(p):
    """Resolve a scripts.yaml path: expand $VARS and ~, then treat a relative
    path as relative to INETGPL_ROOT, so the configuration is not tied to one
    machine's directory layout.
    """
    p = os.path.expanduser(os.path.expandvars(p))
    if not os.path.isabs(p):
        p = os.path.join(INETGPL_ROOT, p)
    return os.path.normpath(p)


def load_config():
    with open(os.path.join(PROTOCOL_DIR, "scripts.yaml")) as f:
        cfg = yaml.safe_load(f)
    for script_set in cfg["script_sets"].values():
        script_set["path"] = resolve_path(script_set["path"])
    # packetdrill has no --version, so the resolved binary path is the only
    # fingerprint of the binary that runs. Record where it
    # was actually found rather than a hardcoded location.
    binary = cfg["environment"].get("packetdrill_binary") or "packetdrill"
    cfg["environment"]["packetdrill_binary"] = (
        binary if os.path.isabs(binary) else (shutil.which(binary) or binary))
    # Optional: a local kernel checkout to prefix the report's source hints with.
    src_root = cfg["environment"].get("kernel_source_root") or ""
    cfg["environment"]["kernel_source_root"] = resolve_path(src_root) if src_root else ""
    # The INET and inet-gpl commits of the report: read from the checkouts that
    # run, because a value written into a file becomes wrong at the next commit.
    for env_var, key in (("INET_ROOT", "inet_commit"), ("INETGPL_ROOT", "inetgpl_commit")):
        cfg["environment"][key] = _live_commit(env_var) or "unknown"
    return cfg


def load_mapping():
    path = os.path.join(PROTOCOL_DIR, "sysctls.yaml")
    if not os.path.exists(path):
        return {"sysctl": {}, "option": {}, "ignore": [], "required": []}
    with open(path) as f:
        return yaml.safe_load(f)


def iter_scripts(cfg, filter_re=None):
    """Yield (set_name, script_id, abspath) for every .pkt in the pinned script_sets.

    script_id is the relative path (no .pkt suffix) inside the set's folder,
    e.g. "tcp_basic_client" or "fast_retransmit/fr-4pkt". The filter matches the
    script's key, its path below tests/protocol (script_key()).
    """
    pattern = re.compile(filter_re) if filter_re else None
    for set_name, script_set in sorted(cfg["script_sets"].items()):
        root = os.path.join(script_set["path"], script_set["subdir"])
        # Fail loudly: a mislocated script set would otherwise glob to nothing and
        # look like a set with zero scripts.
        if not os.path.isdir(root):
            sys.exit(f"script set '{set_name}' not found at {root}\n"
                     f"  (scripts.yaml resolves relative paths against INETGPL_ROOT={INETGPL_ROOT})")
        for path in sorted(glob.glob(os.path.join(root, "**", "*.pkt"), recursive=True)):
            script_id = os.path.relpath(path, root)[: -len(".pkt")]
            key = script_key(path)
            if pattern and not pattern.search(key):
                continue
            yield set_name, script_id, path


def script_key(path):
    """A script's id: its path below tests/protocol, without .pkt."""
    return os.path.relpath(path, SCRIPTS_ROOT)[: -len(".pkt")]


def script_key_to_filename(key):
    return key.replace("/", "__") + ".json"


def sha256_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


# The Linux run's results: one row per script, and a header of "# name: value" lines
# that says which kernel and which packetdrill produced them. A row holds what the
# other commands need -- the verdict, and the sha256 of the script that ran -- and
# nothing that identifies a machine or a person.
LINUX_RESULTS = os.path.join(PROTOCOL_DIR, "linux-results.csv")
LINUX_RESULTS_INTRO = (
    "# The Linux run of every script on the pinned kernel: one row per script. `suite.py linux`\n"
    "# writes it, and the other commands read it. `sha256` is the script\n"
    "# the run executed, `detail` the first line of packetdrill's diagnostic when it did not pass.\n")
RESULT_TO_VERDICT = {"pass": "LINUX_PASS", "fail": "LINUX_FAIL", "error": "LINUX_ERROR"}
VERDICT_TO_RESULT = {v: k for k, v in RESULT_TO_VERDICT.items()}


def read_linux_results():
    """Returns (meta, rows): meta holds the header's kernel, packetdrill and recorded
    values; rows maps a script's id to a record in the shape the other commands
    use -- verdict, script_sha256, diagnostic."""
    meta, rows = {}, {}
    if not os.path.exists(LINUX_RESULTS):
        return meta, rows
    with open(LINUX_RESULTS, newline="") as f:
        lines = f.read().splitlines()
    for line in lines:
        m = re.match(r"^# (kernel|packetdrill|recorded): (.*)$", line)
        if m:
            meta[m.group(1)] = m.group(2).strip()
    for r in csv.DictReader(l for l in lines if not l.startswith("#")):
        rows[r["script"]] = {"verdict": RESULT_TO_VERDICT[r["result"]],
                             "script_sha256": r["sha256"],
                             "diagnostic": r["detail"] or None}
    return meta, rows


def write_linux_results(meta, rows):
    with open(LINUX_RESULTS, "w", newline="") as f:
        f.write(LINUX_RESULTS_INTRO)
        for name in ("kernel", "packetdrill", "recorded"):
            f.write(f"# {name}: {meta.get(name, 'unknown')}\n")
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["script", "sha256", "result", "detail"])
        for key in sorted(rows):
            r = rows[key]
            detail = (r.get("diagnostic") or "").strip().splitlines()
            w.writerow([key, r["script_sha256"], VERDICT_TO_RESULT[r["verdict"]],
                        detail[0][:160] if detail and r["verdict"] != "LINUX_PASS" else ""])


# A path to a helper file inside a backtick block: `./defaults.sh`, `../../common/set_sysctls.py ...`
HELPER_REF_RE = re.compile(r"((?:\.\.?/)+(?:[\w.-]+/)*[\w.-]+\.(?:sh|py))\b")


def preamble_sysctls(cfg, set_name):
    """The sysctls a script of this set runs under: its defaults.sh (the defaults block's
    shared settings and the set's own), plus the kernel defaults the INET run must mirror."""
    d = cfg["defaults"]
    return {**d["sysctls"], **(d["sets"].get(set_name) or {}), **(d.get("kernel") or {})}


def defaults_sh(cfg, set_name):
    """The defaults.sh the Linux run executes for a script of this set, written from the defaults block."""
    d, script_set = cfg["defaults"], cfg["script_sets"][set_name]
    settings = {**d["sysctls"], **(d["sets"].get(set_name) or {})}
    return ("#!/bin/bash\n"
            f"# Written by tests/packetdrill/suite.py from tcp/scripts.yaml's defaults block, set\n"
            f"# {set_name}. It stands in for the defaults.sh of {script_set['upstream_url']}\n"
            f"# ({script_set['upstream_path']}).\n"
            + "".join(f"{c}\n" for c in d["commands"])
            + "".join(f"sysctl -q {k}={shlex.quote(str(v))}\n" for k, v in settings.items()))


def stage_scripts(cfg, dest):
    """Copy every script into `dest` in upstream's shape, with the helper files its
    backtick blocks call by relative path (scripts.yaml's `helpers` of each set),
    and return {original path: staged path}. Only the Linux run executes the helpers; the
    scripts' own folders hold nothing but .pkt files, so the helpers are placed
    here, around a copy."""
    staged = {}
    for name, script_set in sorted(cfg["script_sets"].items()):
        root = os.path.join(script_set["path"], script_set["subdir"])
        stage_root = os.path.join(dest, name)
        for path in sorted(glob.glob(os.path.join(root, "**", "*.pkt"), recursive=True)):
            dst = os.path.join(stage_root, os.path.relpath(path, root))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(path, dst)
            staged[path] = dst
        for target, source in (script_set.get("helpers") or {}).items():
            dst = os.path.normpath(os.path.join(stage_root, target))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if source == "defaults":
                with open(dst, "w") as f:
                    f.write(defaults_sh(cfg, name))
                os.chmod(dst, 0o755)
            else:
                shutil.copy2(os.path.join(PROTOCOL_DIR, source), dst)
    return staged


def unresolved_helpers(staged):
    """The helper references of the staged scripts that point at no file."""
    missing = []
    for path, dst in sorted(staged.items()):
        text = open(dst, encoding="utf-8", errors="replace").read()
        for block in re.findall(r"`([^`]*)`", text):   # timed blocks call helpers too
            for ref in HELPER_REF_RE.findall(block):
                if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(dst), ref))):
                    missing.append(f"{script_key(path)}: {ref}")
    return missing


def cmd_verify_scripts(args):
    """Check the scripts against the Linux results that were recorded from them.

    Each row stores the sha256 of the script the Linux run executed. Re-hashing the
    scripts proves they are byte-for-byte the ones the checked-in results were
    measured on -- the guard that catches a re-pin whose results were not
    re-recorded (or vice versa).
    """
    cfg = load_config()
    meta, rows = read_linux_results()
    by_key = {script_key(p): p for c, s, p in iter_scripts(cfg, args.filter)}

    checked = missing = mismatched = 0
    for key, row in sorted(rows.items()):
        if args.filter and key not in by_key:
            continue
        script_path = by_key.get(key)
        if script_path is None:
            print(f"MISSING  {key}: recorded in linux-results.csv, not among the scripts")
            missing += 1
            continue
        checked += 1
        actual = sha256_of(script_path)
        if actual != row["script_sha256"]:
            print(f"MISMATCH {key}\n  recorded: {row['script_sha256']}\n  script  : {actual}")
            mismatched += 1

    print(f"\nverified {checked} scripts against linux-results.csv (Linux {meta.get('kernel', '?')}): "
          f"{mismatched} mismatched, {missing} missing")
    # the tree the Linux run executes in: every helper a script calls must be where it looks
    with tempfile.TemporaryDirectory() as stage_dir:
        staged = stage_scripts(cfg, stage_dir)
        unresolved = unresolved_helpers(staged)
    for ref in unresolved:
        print(f"UNRESOLVED {ref}")
    print(f"staged {len(staged)} scripts for the Linux run: {len(unresolved)} helper references unresolved")
    missing += len(unresolved)
    if mismatched or missing:
        sys.exit(
            "The scripts and the Linux results disagree. Either the scripts were re-copied "
            "without re-recording the Linux run (run 'make linux'), or the results came from "
            "a different upstream commit than scripts.yaml pins."
        )


# ---------------------------------------------------------------------------
# The Linux run: the real kernel, through upstream packetdrill, unprivileged.
# ---------------------------------------------------------------------------

DIVERGENCE_RE = re.compile(
    r"^(?P<script>.*?):(?P<line>\d+): error handling packet: "
    r"(?:live packet field (?P<field>\S+): )?(?P<message>.*)$"
)


def parse_linux_diagnostic(stderr_text):
    """Extract packetdrill's field-diff diagnostic from stderr, if present."""
    lines = stderr_text.splitlines()
    divergence = None
    for i, line in enumerate(lines):
        m = DIVERGENCE_RE.match(line)
        if m:
            divergence = {
                "script_line": int(m.group("line")),
                "message": m.group("message"),
                "expected_packet": None,
                "actual_packet": None,
                "context_log": lines[max(0, i - 5): i + 1],
            }
            # Following lines are typically "script packet:" / "actual packet:"
            for j in range(i + 1, min(i + 4, len(lines))):
                if lines[j].strip().startswith("script packet:"):
                    divergence["expected_packet"] = lines[j].split(":", 1)[1].strip()
                elif lines[j].strip().startswith("actual packet:"):
                    divergence["actual_packet"] = lines[j].split(":", 1)[1].strip()
            break
    return divergence


def script_declared_options(script_path):
    """The `--option` names a script sets for itself, e.g. {"--local_ip", ...}.

    packetdrill's parse_and_finalize_config() parses the script's options FIRST
    and then the command line, whose own comment says "Command line options
    overwrite options in script" -- so anything we pass unconditionally silently
    beats what the script asked for. Callers use this to stand down.
    """
    try:
        with open(script_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return set()
    # OPTION_LINE_RE captures the whole option including any "=value"; the name
    # alone is what identifies a clash with one of ours.
    return {m.group(1).split("=", 1)[0] for m in OPTION_LINE_RE.finditer(text)}


def linux_flags(script_path, tolerance_usecs):
    """The protocol's LINUX_FLAGS minus whatever the script configures itself, plus a tolerance.

    The seven TFO-cookie scripts (fastopen/server/{,opt34/}simple1-3,
    sockopt-fastopen-key) are the reason this exists: a Fast Open cookie is
    aes(master_key, local_ip, remote_ip), and each of them picks its own IP pair
    to pin a specific cookie. Forcing --local_ip/--remote_ip on top made all
    seven compute the same wrong cookie. `--tolerance_usecs` is the same trap in
    slow motion (cubic-bulk-166k asks for 20000, we were replacing it with
    50000). -D defines are NOT filtered: scripts cannot set those, and an unused
    define is harmless.
    """
    own = script_declared_options(script_path)
    flags, keep_next = [], False
    for flag in PROTOCOL_RULES.LINUX_FLAGS:
        if keep_next:               # the value half of a "-D", "NAME=value" pair
            keep_next = False
            flags.append(flag)
        elif flag == "-D":
            keep_next = True
            flags.append(flag)
        elif flag.split("=", 1)[0] not in own:
            flags.append(flag)
    if "--tolerance_usecs" not in own:
        flags.append(f"--tolerance_usecs={tolerance_usecs}")
    return flags


def run_linux(script_path, tolerance_usecs=DEFAULT_TOLERANCE_USECS, binary="packetdrill",
                  privileged=False):
    """Run one script against the real kernel in a fresh netns.

    The unprivileged recipe: `ulimit -s 2048` avoids an
    mlockall()/RLIMIT_MEMLOCK conflict (packetdrill mlockall()s itself; the
    default 8 MB thread stack blows the 8 MB memlock hard limit under an
    unprivileged user namespace). Do not "fix" this by zeroing memlock instead
    -- packetdrill aborts if mlockall fails.

    Privileged mode trades the fake root of `unshare -r` for real root via sudo,
    which is the only way to run five of the scripts (see PRIVILEGED_*
    below). It lifts the memlock limit instead of shrinking the stack around it,
    so a script whose read() needs a multi-megabyte locked buffer can allocate
    one. Everything else is identical -- same netns isolation, same flags.

    cwd is the script's own directory so its backtick init scripts (e.g.
    `./defaults.sh`, `../common/defaults.sh`) resolve their relative paths.
    """
    script_dir = os.path.dirname(script_path)
    script_name = os.path.basename(script_path)
    # `binary` is the resolved environment.packetdrill_binary from scripts.yaml:
    # the binary that actually runs (not a bare PATH lookup that could pick a
    # different build).
    cmd = [binary] + linux_flags(script_path, tolerance_usecs) + [script_name]
    # Give nstat a private history file. Six scripts call it, and left to
    # itself it derives the path from getuid() -- which is 0 BOTH inside
    # `unshare -r` (the mapped fake root) and under real root, so both modes
    # land on /tmp/.nstat.u0. The unprivileged runs create it owned by the real
    # user; a later privileged run then opens the same path as root and, because
    # /tmp is sticky and fs.protected_regular=1 applies to root too, gets EACCES
    # -- "nstat: open history file: Permission denied", which aborts the script's
    # init command. A per-invocation file removes the shared state entirely.
    # Privileged mode is the unprivileged recipe PLUS one privilege, never a
    # different recipe: `ulimit -s 2048` stays. It is not only about fitting
    # under the memlock cap -- packetdrill's behavior is measurably
    # stack-size-dependent, and eor/no-coalesce-retrans fails deterministically
    # (3/3) at `-s 6144` while passing at 2048 and 4096. Dropping the stack
    # limit here once gave two false LINUX_FAIL results.
    ulimit = "ulimit -s 2048" + ("; ulimit -l unlimited" if privileged else "")
    inner = ('NSTAT_HISTORY="${TMPDIR:-/tmp}/.nstat.packetdrill.$$"; export NSTAT_HISTORY; '
             'ip link set lo up; ' + ulimit + '; ' + shlex.join(cmd) + '; '
             'status=$?; rm -f "$NSTAT_HISTORY"; exit $status')
    if privileged:
        full_cmd = ["sudo", "-n", "unshare", "-n", "sh", "-c", inner]
    else:
        full_cmd = ["unshare", "-r", "-n", "sh", "-c", inner]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            full_cmd, cwd=script_dir, capture_output=True, text=True,
            timeout=LINUX_RUN_TIMEOUT_S,
        )
        duration = time.monotonic() - start
    except subprocess.TimeoutExpired:
        return {
            "verdict": "LINUX_ERROR",
            "duration_s": LINUX_RUN_TIMEOUT_S,
            "diagnostic": f"timed out after {LINUX_RUN_TIMEOUT_S}s",
            "divergence": None,
        }

    output = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return {"verdict": "LINUX_PASS", "duration_s": duration, "diagnostic": None, "divergence": None}

    divergence = parse_linux_diagnostic(output)
    if divergence is not None:
        return {
            "verdict": "LINUX_FAIL", "duration_s": duration,
            "diagnostic": divergence["message"], "divergence": divergence,
        }
    # Nonzero exit with no recognized field-diff pattern: infra/harness problem
    # (e.g. init script failure, unsupported syscall) rather than a genuine
    # protocol divergence -- keep it separate so it doesn't pollute DIVERGENCE stats.
    return {
        "verdict": "LINUX_ERROR", "duration_s": duration,
        "diagnostic": output.strip()[-2000:], "divergence": None,
    }




def snapshot_module_params():
    saved = {}
    for d in PROTOCOL_RULES.MODULE_PARAM_DIRS:
        for name in sorted(glob.glob(os.path.join(d, "*"))):
            if not os.access(name, os.W_OK) and not os.path.isfile(name):
                continue
            try:
                with open(name) as f:
                    saved[name] = f.read().strip()
            except OSError:
                pass  # write-only or unreadable: nothing to restore either
    return saved


def restore_module_params(saved):
    for name, value in saved.items():
        try:
            with open(name) as f:
                if f.read().strip() == value:
                    continue
        except OSError:
            continue
        print(f"  restoring {name} -> {value}")
        subprocess.run(["sudo", "-n", "sh", "-c", f"echo {shlex.quote(value)} > {shlex.quote(name)}"],
                       capture_output=True, text=True)


def cmd_linux(args):
    cfg = load_config()
    kernel_release = os.uname().release
    meta, rows = read_linux_results()
    if args.filter and meta.get("kernel") not in (None, kernel_release):
        sys.exit(f"linux-results.csv holds Linux {meta['kernel']}, this is {kernel_release}: a filtered "
                 f"run would mix two kernels in one file. Run without --filter.")
    if not args.filter:
        rows = {}
    meta = {"kernel": kernel_release,
            "packetdrill": cfg["environment"].get("packetdrill_commit") or "unknown",
            "recorded": time.strftime("%Y-%m-%d")}

    privileged = getattr(args, "privileged", False)
    if privileged:
        # Only packetdrill is meant to run as root. Running the suite itself
        # under sudo breaks the interpreter lookup (root's secure_path finds a
        # python3 that PyYAML is not installed for) and would write linux-results.csv
        # into the repository root-owned.
        if os.geteuid() == 0:
            sys.exit("run the suite as yourself, not under sudo -- --privileged already\n"
                     "  sudoes the packetdrill invocation itself. Running the whole suite as\n"
                     "  root writes linux-results.csv root-owned and resolves a different python3.")
        probe = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
        if probe.returncode != 0:
            sys.exit("--privileged needs passwordless sudo; `sudo -n true` failed:\n"
                     + (probe.stderr or "").strip() +
                     "\n  (this runs `sudo -n unshare -n packetdrill ...` per script;\n"
                     "   configure NOPASSWD for those, or run the Linux run without --privileged)")
    saved_params = snapshot_module_params() if privileged else {}

    scripts = list(iter_scripts(cfg, args.filter))
    # the Linux run executes each script from a copy that has its helper files around it
    stage_dir = os.path.join(SUITE_DIR, "out", "linux-stage")
    shutil.rmtree(stage_dir, ignore_errors=True)
    staged = stage_scripts(cfg, stage_dir)
    print(f"Linux run over {len(scripts)} scripts, kernel {kernel_release}"
          f"{', PRIVILEGED' if privileged else ''}...")
    counts = {}
    for i, (set_name, script_id, path) in enumerate(scripts, 1):
        skip_key = script_key(path)
        if skip_key in (cfg.get("skips") or {}):
            continue
        result = run_linux(staged[path], args.tolerance_usecs, cfg["environment"]["packetdrill_binary"],
                               privileged)
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        rows[skip_key] = {"verdict": result["verdict"], "script_sha256": sha256_of(path),
                          "diagnostic": result["diagnostic"]}
        # written after every script, so an interrupted run keeps what it measured
        write_linux_results(meta, rows)
        print(f"  [{i}/{len(scripts)}] {skip_key}: {result['verdict']}")

    if saved_params:
        restore_module_params(saved_params)

    print("\n=== Linux run summary ===")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict}: {n}")
    print(f"results written to {LINUX_RESULTS}")


# ---------------------------------------------------------------------------
# Preprocessing: strip constructs the INET-fork parser can't read at all
# (backtick shell blocks, leading --option lines), resolve them to a sysctl/
# option set, and translate that set into INET ini overrides via tcp/sysctls.yaml.
# ---------------------------------------------------------------------------

# Only UNTIMED backtick blocks (the line's first non-blank char is the
# backtick) are stripped and hoisted into the global sysctl set: those are
# the head preamble (defaults.sh + sysctl lines) and the tail
# /tmp/sysctl_restore_$PPID.sh call. A TIMED backtick line ("+.07 `sysctl
# -q net.ipv4.tcp_timestamps=0`") is a mid-script COMMAND event: hoisting
# it misconfigures the connections BEFORE it (zerocopy/fastopen-client's
# first connection expects TS on) and deleting it shifts every later
# relative timestamp. The INET-fork parser reads backtick commands natively
# (BACK_QUOTED -> command_spec -> COMMAND_EVENT), so timed blocks stay in
# the script; PacketDrillApp applies the known-sysctl subset at runtime.
BACKTICK_RE = re.compile(r"(?m)^[ \t]*`([^`]*)`[^\n]*\n?")
OPTION_LINE_RE = re.compile(r"(?m)^[ \t]*(--[a-zA-Z_][a-zA-Z_0-9]*(?:=\S+)?)[ \t]*(?://.*)?$")
SYSCTL_LINE_RE = re.compile(r"^sysctl\s+-q\s+(.*)$")
# The scripts' other sysctl mechanism: a helper script that pokes /proc/sys
# directly, e.g. `../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0
# /proc/sys/net/ipv4/tcp_ecn=1`. Same key=value assignments as `sysctl -q`, but
# the keys are /proc/sys/ paths (stripped below). 59 scripts use it, 32
# to set tcp_timestamps=0 -- without this they kept INET's default TS on and
# emitted an extra SYN option.
SET_SYSCTLS_RE = re.compile(r"set_sysctls\.py\s+(.+)$")
SYSCTL_ASSIGN_RE = re.compile(r'([a-zA-Z0-9_./]+)=("(?:[^"\\]|\\.)*"|\S+)')
PROC_SYS_PREFIX_RE = re.compile(r"^/?proc/sys/")


# The first line of a preamble block that sources a set's defaults.sh
DEFAULTS_REF_RE = re.compile(r"(?:\.\.?/)+(?:common/)?defaults\.sh")


def preprocess_script(text, preamble):
    """Strip backtick blocks and leading --option lines; resolve backtick
    blocks to a sysctl dict: a block that sources defaults.sh gives `preamble`,
    the sysctls of the script's set (preamble_sysctls), and a best-effort
    line-by-line `sysctl -q k=v [k2=v2 ...]` scan covers the rest.

    Returns (clean_text, stripped) where stripped = {backtick_blocks: [...],
    options: [...], sysctls: {...}}.
    """
    stripped = {"backtick_blocks": [], "options": [], "sysctls": {}}

    def repl_backtick(m):
        stripped["backtick_blocks"].append(m.group(1).strip())
        return ""

    text2 = BACKTICK_RE.sub(repl_backtick, text)

    def repl_option(m):
        stripped["options"].append(m.group(1))
        return ""

    text2 = OPTION_LINE_RE.sub(repl_option, text2)

    for content in stripped["backtick_blocks"]:
        # A preamble (defaults.sh) may be FOLLOWED by explicit sysctl lines in
        # the same backtick block (the usual shape of the accecn scripts). Match the
        # preamble against the first line only, apply its preset, then
        # line-scan the rest so explicit sysctls layer on top of (and
        # override) the preset -- previously a whole-content anchored match
        # dropped the preset entirely for such mixed blocks.
        # join backslash-continued lines first: multi-line set_sysctls.py
        # invocations ("set_sysctls.py \\\n  /proc/sys/... \\\n  ...") must
        # line-scan as ONE logical line, or every continued assignment is lost
        content = re.sub(r"\\\s*\n\s*", " ", content)
        lines = content.splitlines()
        rest = lines
        if lines and DEFAULTS_REF_RE.fullmatch(lines[0].strip()):
            stripped["sysctls"].update(preamble)
            rest = lines[1:]
        for line in rest:
            line = line.strip()
            # device-MTU preamble line (e.g. syncookies_ip4_9k's
            # "ip link set dev tun0 mtu 9000"): the DUT's advertised MSS
            # becomes MTU - 40; carried as a pseudo-knob for translate_to_ini
            mtu_m = re.match(r"ip\s+link\s+set\s+dev\s+\S+\s+mtu\s+(\d+)", line)
            if mtu_m:
                stripped["sysctls"]["__tun_mtu"] = mtu_m.group(1)
                continue
            # per-route attributes (`ip route change <dst> ... advmss N mtu [lock] M
            # initcwnd K`). Linux keeps these in the dst entry: advmss is the MSS the
            # DUT announces, the route MTU is the ceiling RFC 4821 probing works up
            # to, and initcwnd is the initial congestion window in segments.
            if re.match(r"ip\s+route\s+(change|add|replace)\b", line):
                for attr, knob in (("advmss", "__route_advmss"),
                                   ("initcwnd", "__route_initcwnd")):
                    am = re.search(r"\b%s\s+(\d+)" % attr, line)
                    if am:
                        stripped["sysctls"][knob] = am.group(1)
                am = re.search(r"\bmtu\s+(?:lock\s+)?(\d+)", line)
                if am:
                    stripped["sysctls"]["__route_mtu"] = am.group(1)
                continue
            m = SYSCTL_LINE_RE.match(line)
            sm = SET_SYSCTLS_RE.search(line) if not m else None
            if not m and not sm:
                continue
            for am in SYSCTL_ASSIGN_RE.finditer((m or sm).group(1)):
                key = PROC_SYS_PREFIX_RE.sub("", am.group(1))  # set_sysctls.py uses /proc/sys/net/ipv4/x paths
                key = key.replace("/", ".")  # sysctl accepts both net/ipv4/x and net.ipv4.x
                stripped["sysctls"][key] = am.group(2).strip('"')

    return text2, stripped


def translate_to_ini(stripped, mapping):
    """Translate a preprocessed script's sysctls/options into INET ini
    overrides. Returns (ini_overrides, unmapped_knobs, blocking_reasons).
    blocking_reasons non-empty means the caller should classify this script
    INET_UNSUPPORTED_CONFIG instead of running it.
    """
    ini = {}
    unmapped = []
    blocking = []
    PROTOCOL_RULES.translate_special(stripped["sysctls"], ini)
    smap = mapping.get("sysctl", {})
    omap = mapping.get("option", {})
    ignore = set(mapping.get("ignore", []))
    required = set(mapping.get("required", []))

    for key, val in stripped["sysctls"].items():
        spec = smap.get(key)
        if spec is not None:
            transform = spec["transform"]
            if transform == "bool":
                truthy = val.strip() not in ("0", "", "0x0")
                ini[spec["ini"]] = "true" if truthy else "false"
            elif transform == "int":
                v = val.strip()
                # optional special-value remap (e.g. Linux's UINT_MAX-means-
                # disabled tcp_notsent_lowat -> INET's -1) and unit suffix
                # (e.g. "B" for @unit(B) NED params)
                v = spec.get("special", {}).get(v, v)
                ini[spec["ini"]] = v + spec.get("suffix", "")
            elif transform == "string":
                # quoted verbatim string param (e.g. the Fast Open key);
                # Linux allows "primary,backup" -- INET models the primary only
                v = val.strip().strip('"').split(",")[0]
                ini[spec["ini"]] = '"' + v + '"'
            elif transform == "enum":
                mapped = spec.get("values", {}).get(val.strip())
                if mapped is not None:
                    ini[spec["ini"]] = mapped
                else:
                    unmapped.append(f"{key}={val}")
                    if key in required or spec.get("required"):
                        blocking.append(f"{key}={val} (no INET equivalent)")
            elif transform == "bitmask":
                try:
                    ival = int(val.strip(), 0)
                except ValueError:
                    unmapped.append(f"{key}={val}")
                    if key in required or spec.get("required"):
                        blocking.append(f"{key}={val} (not an integer)")
                else:
                    for bit_str, bit_ini in spec.get("bits", {}).items():
                        truthy = "true" if (ival & int(bit_str, 0)) else "false"
                        bit_inis = bit_ini if isinstance(bit_ini, list) else [bit_ini]
                        for one_ini in bit_inis:
                            ini[one_ini] = truthy
            else:
                unmapped.append(f"{key}={val}")
        elif key in ignore:
            continue
        else:
            unmapped.append(f"{key}={val}")
            if key in required:
                blocking.append(f"{key}={val} (unmapped, required)")

    for opt in stripped["options"]:
        flag, _, val = opt.partition("=")
        val = val if "=" in opt else None
        spec = omap.get(flag)
        if spec is None:
            unmapped.append(opt)
            if flag in required:
                blocking.append(f"{opt} (unmapped, required)")
            continue
        if spec.get("transform") == "ignore" or spec.get("ini") is None:
            unmapped.append(opt)
            continue
        if val is not None:
            ini[spec["ini"]] = ('"' + val + '"') if spec.get("quoted") else val

    return ini, unmapped, blocking


def cmd_preprocess(args):
    """Dry-run helper for debugging: preprocess every
    matched script and report unmapped-knob / blocking-config statistics
    without running anything.
    """
    cfg = load_config()
    mapping = load_mapping()
    scripts = list(iter_scripts(cfg, args.filter))
    n_ok, n_blocked = 0, 0
    unmapped_counter = {}
    for set_name, script_id, path in scripts:
        text = open(path, encoding="utf-8", errors="replace").read()
        _, stripped = preprocess_script(text, preamble_sysctls(cfg, set_name))
        _, unmapped, blocking = translate_to_ini(stripped, mapping)
        for u in unmapped:
            key = u.split("=", 1)[0]
            unmapped_counter[key] = unmapped_counter.get(key, 0) + 1
        if blocking:
            n_blocked += 1
            if args.verbose:
                print(f"BLOCKED {script_key(path)}: {blocking}")
        else:
            n_ok += 1
    print(f"\npreprocessed {len(scripts)} scripts: {n_ok} translatable, {n_blocked} blocked")
    print("\nunmapped knob frequency (informational, non-blocking unless noted above):")
    for key, n in sorted(unmapped_counter.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {key}")


# ---------------------------------------------------------------------------
# The INET run: the preprocessed script through INET's PacketDrillApp.
# ---------------------------------------------------------------------------

DIALECT_ERROR_RE = re.compile(r"parse error at '(?P<token>.*?)'|Error parsing the script")
DIVERGENCE_RE_INET = re.compile(r"Packetdrill error:\s*(?P<message>.*)")
# Emitted by PacketDrillApp::finish() when the simulation ended with script
# events left unconsumed (an expected outbound packet never arrived, a %{ }%
# block never ran, a GSO super-segment was left half-matched). Checked AFTER
# the divergence regex: a thrown divergence aborts the run mid-script, so the
# marker fires then too, but the divergence is the actual root cause.
STALLED_RE_INET = re.compile(r"PacketDrill script INCOMPLETE:\s*(?P<message>.*)")


def require_env():
    for var in ("INET_ROOT", "INETGPL_ROOT"):
        if not os.environ.get(var):
            sys.exit(
                f"{var} is not set. Run:\n"
                f"  cd $INET_ROOT && source setenv -q && cd $INETGPL_ROOT && source setenv -q\n"
                f"(both, in this order, in the same shell) before invoking suite.py."
            )
    if not os.path.exists(runner_path()):
        sys.exit(
            f"{runner_path()} not found. Build it once:\n"
            f"  {BUILD_CMD}"
        )


def classify_inet_output(output, returncode, blocking_reasons):
    """Classify the INET run's output per the taxonomy in the plan (order matters:
    dialect check before config-block check before crash check before
    divergence, since a dialect failure's log also often contains generic
    <!> Error noise that would otherwise misclassify as INET_CRASH).

    Reaching "Simulation time limit reached" is NOT a failure signal here --
    PacketDrillApp never calls endSimulation() itself, so hitting the
    configured limit is how every run ends, success or not (see
    INET_RUN_SIM_TIME_LIMIT). This mirrors the pass/fail discipline the 10
    legacy packetdrill tests already use (tests/packetdrill/tcp/*.test:
    `%not-contains: test.out / Packetdrill error:`): absence of a
    "Packetdrill error:" string (and absence of any other unrelated <!>
    Error) is what PASS means, not how the run terminated.
    """
    if blocking_reasons:
        return "INET_UNSUPPORTED_CONFIG", "; ".join(blocking_reasons)
    m = DIALECT_ERROR_RE.search(output)
    if m:
        detail = m.group(0)
        return "INET_DIALECT", detail
    m = DIVERGENCE_RE_INET.search(output)
    if m:
        return "INET_DIVERGE", m.group("message").strip()
    m = STALLED_RE_INET.search(output)
    if m:
        return "INET_STALLED", m.group("message").strip()
    generic_errors = [
        l for l in output.splitlines()
        if l.strip().startswith("<!>") and "Simulation time limit reached" not in l
    ]
    if returncode != 0 or generic_errors:
        return "INET_CRASH", (generic_errors[0] if generic_errors else output.strip()[-500:])
    return "INET_PASS", None


def extract_inet_divergence_context(output):
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "Packetdrill error:" in line:
            # Include lines AFTER the error marker too: for %{ }% assertion
            # failures the actual Python traceback (assert expression, values)
            # is printed after "Packetdrill error:", and cutting at the marker
            # used to discard it -- leaving only a useless bare "Traceback
            # (most recent call last):" as the message.
            return {
                "script_line": None,
                "message": line.split("Packetdrill error:", 1)[1].strip(),
                "expected_packet": None,
                "actual_packet": None,
                "context_log": lines[max(0, i - 30): i + 25],
            }
    return None


def prepare_inet_run(script_id, path, mapping, preamble):
    """Everything the INET run decides before it starts: the script without its untimed preamble, and
    the ini overrides, unmapped knobs and blocking reasons of this script. The INET run and the
    generator of INET's wrappers both call this, so a wrapper's expected result comes from
    the same rules as the run."""
    text = open(path, encoding="utf-8", errors="replace").read()
    clean_text, stripped = preprocess_script(text, preamble)
    ini_overrides, unmapped, blocking = translate_to_ini(stripped, mapping)

    PROTOCOL_RULES.adjust_inet_run(script_id, clean_text, ini_overrides, blocking)
    return clean_text, stripped, ini_overrides, unmapped, blocking


def run_inet(set_name, script_id, path, mapping, preamble, preproc_dir, pcap_file=None):
    require_env()
    clean_text, stripped, ini_overrides, unmapped, blocking = prepare_inet_run(script_id, path, mapping, preamble)

    pp_name = script_key_to_filename(script_key(path))[: -len(".json")] + ".pkt"
    pp_path = os.path.join(preproc_dir, pp_name)
    os.makedirs(preproc_dir, exist_ok=True)
    # base.ini points the PcapRecorder at out/pcap/ (a debugging aid; one file,
    # overwritten per run). PcapRecorder opens it eagerly in initialize() and
    # aborts if the directory is missing -- which it is on a bare checkout or
    # right after `make clean` (out/ is a run artifact).
    os.makedirs(os.path.join(SUITE_DIR, "out", "pcap"), exist_ok=True)
    with open(pp_path, "w") as f:
        f.write(clean_text)

    result_common = {
        "stripped_preamble": stripped,
        "ini_overrides": ini_overrides,
        "unmapped_knobs": unmapped,
    }

    if blocking:
        return {
            "verdict": "INET_UNSUPPORTED_CONFIG", "duration_s": 0.0,
            "diagnostic": "; ".join(blocking), "divergence": None, "output": "",
            **result_common,
        }

    ned_path = f"{os.environ['INET_ROOT']}/src;{os.environ['INETGPL_ROOT']}/src;{SUITE_DIR}/ned"
    cmd = [
        runner_path(), "-u", "Cmdenv", "-f", os.path.join(SUITE_DIR, "ini", "base.ini"),
        "-f", os.path.join(PROTOCOL_DIR, PROTOCOL + ".ini"),
        "-n", ned_path, "--cmdenv-interactive=false",
        f'--**.scriptFile="{pp_path}"',
        f"--sim-time-limit={INET_RUN_SIM_TIME_LIMIT}",
    ]
    for key, val in ini_overrides.items():
        cmd.append(f"--{key}={val}")
    # A caller that runs scripts in parallel gives each run its own capture file;
    # base.ini's single path would be written by every run at once.
    if pcap_file:
        cmd.append(f'--**.pdhost.pcapRecorder[0].pcapFile="{pcap_file}"')

    start = time.monotonic()
    try:
        # errors='replace': the simulation's stdout can carry non-UTF-8 bytes (e.g. raw
        # payload echoed into an EV line); a decode error must not abort the whole run.
        proc = subprocess.run(cmd, cwd=SUITE_DIR, capture_output=True, text=True,
                              errors='replace', timeout=INET_RUN_TIMEOUT_S)
        duration = time.monotonic() - start
        output = proc.stdout + proc.stderr
        verdict, detail = classify_inet_output(output, proc.returncode, [])
    except subprocess.TimeoutExpired as e:
        duration = INET_RUN_TIMEOUT_S
        # Even with text=True, TimeoutExpired carries the partial output as raw
        # BYTES (CPython populates it before the decode step) -- concatenating
        # it with str raises TypeError and would abort the whole sweep.
        def _as_text(s):
            return s.decode("utf-8", "replace") if isinstance(s, bytes) else (s or "")
        output = _as_text(e.stdout) + _as_text(e.stderr)
        verdict, detail = "INET_CRASH", f"timed out after {INET_RUN_TIMEOUT_S}s"

    divergence = extract_inet_divergence_context(output) if verdict == "INET_DIVERGE" else None
    return {
        "verdict": verdict, "duration_s": round(duration, 3),
        "diagnostic": detail, "divergence": divergence, "output": output,
        **result_common,
    }


def cmd_inet(args):
    require_env()
    cfg = load_config()
    mapping = load_mapping()
    preproc_dir = os.path.join(SUITE_DIR, "out", "preprocessed")
    results_dir = os.path.join(SUITE_DIR, "out", "inet_results")
    os.makedirs(results_dir, exist_ok=True)

    scripts = list(iter_scripts(cfg, args.filter))
    print(f"INET run over {len(scripts)} scripts...")
    counts = {}
    for i, (set_name, script_id, path) in enumerate(scripts, 1):
        skip_key = script_key(path)
        if skip_key in (cfg.get("skips") or {}):
            continue
        result = run_inet(set_name, script_id, path, mapping,
                              preamble_sysctls(cfg, set_name), preproc_dir)
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        record = {
            "id": skip_key, "script": script_id, "set": set_name,
            "script_sha256": sha256_of(path), "run": "inet",
            "verdict": result["verdict"],
            "runner": {
                "kernel": None, "packetdrill": None,
                "inet_commit": cfg["environment"]["inet_commit"],
                "inetgpl_commit": cfg["environment"]["inetgpl_commit"],
            },
            "duration_s": result["duration_s"],
            "diagnostic": result["diagnostic"],
            "divergence": result["divergence"],
            "stripped_preamble": result["stripped_preamble"],
            "ini_overrides": result["ini_overrides"],
            "unmapped_knobs": result["unmapped_knobs"],
        }
        out_path = os.path.join(results_dir, script_key_to_filename(skip_key))
        with open(out_path, "w") as f:
            json.dump(record, f, indent=2)
            f.write("\n")
        print(f"  [{i}/{len(scripts)}] {skip_key}: {result['verdict']}")

    print("\n=== INET run summary ===")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict}: {n}")
    print(f"results written to {results_dir}")


def cmd_inet_one(args):
    """The INET run of one script, as a test runner calls it.

    Prints the simulation output, then one verdict line that a test can match:
        PACKETDRILL <id>: PASS
        PACKETDRILL <id>: FAIL (<INET run verdict>: <detail>)
    and exits 0 only on a pass. It runs the same preparation and the same
    classification as `inet`, so its verdict is the scoreboard's INET run verdict.
    It records nothing under out/inet_results: a test run must not change the
    inputs of `compare`.
    """
    require_env()
    cfg = load_config()
    mapping = load_mapping()
    key = args.script
    path = os.path.join(SCRIPTS_ROOT, key + ".pkt")
    set_name = script_id = None
    for name, script_set in cfg["script_sets"].items():
        root = os.path.join(script_set["path"], script_set["subdir"])
        if os.path.isfile(path) and os.path.abspath(path).startswith(os.path.abspath(root) + os.sep):
            set_name, script_id = name, os.path.relpath(path, root)[: -len(".pkt")]
    if set_name is None:
        print(f"PACKETDRILL {key}: ERROR (no such script: expected a path below tests/protocol "
              f"without .pkt, such as tcp/linux/tcp_basic_client)")
        sys.exit(2)
    skip = (cfg.get("skips") or {}).get(key)
    if skip:
        print(f"#SKIPPED: scripts.yaml skips {key}: {skip}")
        return
    preproc_dir = os.path.join(SUITE_DIR, "out", "preprocessed")
    pcap_file = os.path.join("out", "pcap", script_key_to_filename(key)[:-len(".json")] + ".pcap")
    result = run_inet(set_name, script_id, path, mapping, preamble_sysctls(cfg, set_name),
                          preproc_dir, pcap_file=pcap_file)
    print(result.get("output", ""))
    if result["verdict"] == "INET_PASS":
        print(f"PACKETDRILL {key}: PASS")
        return
    detail = (result.get("diagnostic") or "").strip().splitlines()
    print(f"PACKETDRILL {key}: FAIL ({result['verdict']}: {detail[0] if detail else 'no detail'})")
    sys.exit(1)


# ---------------------------------------------------------------------------
# INET's wrappers: one .test file per script, at the script's own path below
# INET's tests/protocol.
# ---------------------------------------------------------------------------

def set_folder(script_set):
    """The folder of a script set below tests/protocol, for example tcp/linux. INET keeps the
    set's wrappers in the folder of the same name."""
    return os.path.relpath(resolve_path(script_set["path"]), SCRIPTS_ROOT)


def load_features():
    with open(os.path.join(PROTOCOL_DIR, "features.yaml")) as f:
        return yaml.safe_load(f)


def exercised(features, key, script_id):
    """What a script exercises, from features.yaml: a "scripts" entry whose regex matches the
    key replaces the entry of the script's category. A script with neither stops the run."""
    for pattern, entry in (features.get("scripts") or {}).items():
        if re.search(pattern, key):
            return entry
    category = PROTOCOL_RULES.categorize(script_id)
    entry = (features.get("categories") or {}).get(category)
    if entry is None:
        sys.exit(f"{key}: features.yaml has no entry for category '{category}'")
    return entry


def exercised_lines(entry):
    proto = PROTOCOL.upper()
    named = ", ".join(entry.get("features") or []) or f"none in INET's {proto} feature map"
    lines = [f"Features: {named}"]
    if entry.get("documents"):
        lines.append(f"Not in INET's {proto} catalogs: {', '.join(entry['documents'])}")
    if entry.get("linux"):
        lines.append(f"Linux socket interface, no standard: {', '.join(entry['linux'])}")
    return "\n".join(lines)


def wrapper_text(script_set, key, script_id, linux_row, blocking, entry, release):
    """One INET wrapper. It names the script and matches the verdict line of `inet-one`; it
    holds no line of the script, which is GPL-2.0 and stays here. The wrapper calls
    inet_run_packetdrill, which INET's setenv puts on the PATH: the command gives #SKIPPED
    when inet-gpl is not there, and needs no path that depends on the folder of the test."""
    if blocking:
        expected = "FAIL"
        why = ("Expected result: FAIL. The class is an unimplemented feature: INET cannot run the\n"
               f"script, because of {'; '.join(blocking)}.")
    else:
        expected = "PASS"
        why = "Expected result: PASS."
    return (
        "%description:\n\n"
        "Linux equivalence: the packetdrill script\n\n"
        f"    {key}\n\n"
        f"of inet-gpl (tests/protocol/{key}.pkt), run in INET's PacketDrillApp.\n"
        "This file only names the script; the script itself is GPL-2.0 and stays in inet-gpl.\n\n"
        f"Upstream: {script_set['upstream_url']} at {script_set['git_commit'][:12]},\n"
        f"{script_set['upstream_path']}/{script_id}.pkt.\n"
        f"Linux {release} passes the script (script sha256 {linux_row['script_sha256'][:16]}).\n\n"
        f"{exercised_lines(entry)}\n\n"
        f"{why}\n\n"
        "Generated by `tests/packetdrill/suite.py gen-wrappers` in inet-gpl; do not edit.\n\n"
        f"%# expected-result: {expected}\n\n"
        f"%testprog: inet_run_packetdrill {key}\n\n"
        "%contains: stdout\n"
        f"PACKETDRILL {key}: PASS\n"
    )


def wrappers_readme(set_name, script_set, folder, example, counts, excluded, entries, release):
    """The README of one folder of wrappers: what the wrappers are, what they exercise, and the
    scripts of the set that have no wrapper."""
    proto = PROTOCOL.upper()
    rows = "\n".join(f"| `{key}` | {why} | {reason.strip()} |" for key, why, reason in excluded)
    def tally(field):
        c = collections.Counter(v for e in entries for v in (e.get(field) or []))
        return "\n".join(f"| {k} | {n} |" for k, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))
    return (
        f"# The {proto} packetdrill scripts of {script_set['title']} as protocol tests\n\n"
        "Each `.test` file in this folder is a wrapper for one packetdrill script of inet-gpl: the\n"
        "script with the same path below `tests/protocol/`. For example, this wrapper:\n\n"
        f"    {folder}/{example}.test\n\n"
        "runs this script of inet-gpl:\n\n"
        f"    tests/protocol/{folder}/{example}.pkt\n\n"
        f"inet-gpl copies the scripts from {script_set['upstream_url']} at\n"
        f"`{script_set['git_commit'][:12]}`, folder `{script_set['upstream_path']}/`.\n\n"
        "A wrapper gives the script's id to `inet_run_packetdrill`, which runs the script in INET's\n"
        "`PacketDrillApp` through inet-gpl's `tests/packetdrill/suite.py inet-one`. The wrapper\n"
        "passes when the output ends with `PACKETDRILL <id>: PASS`.\n\n"
        "A pass is **Linux equivalence**, not conformance to an RFC. Linux " f"{release} passes every\n"
        "script that has a wrapper, and a pass says that INET does the same.\n\n"
        "The scripts, the packetdrill parser and the packet comparison are GPL licensed and stay in\n"
        "inet-gpl. These files hold no line of a script. Without inet-gpl, every wrapper gives SKIP:\n\n"
        "```sh\n"
        "cd <inet> && source setenv -q && cd <inet-gpl> && source setenv -q\n"
        f"inet_run_protocol_tests --filter {folder}/\n"
        "```\n\n"
        "`tests/packetdrill/suite.py gen-wrappers` in inet-gpl writes the wrappers and this file, and\n"
        "`suite.py gen-wrappers --check` shows the files that are out of date. Do not edit them by hand.\n\n"
        "## What the wrappers exercise\n\n"
        f"The `Features:` line of a wrapper names ids of INET's {proto} feature map\n"
        f"(`doc/project/evidence/protocol/{PROTOCOL}/features.md`). If a script is outside the map, its\n"
        f"wrapper names the document that INET's {proto} evidence does not catalog, or the Linux\n"
        "socket interface that no standard defines. The map is\n"
        f"`tests/packetdrill/{PROTOCOL}/features.yaml` in inet-gpl. One script can count in more than\n"
        "one row.\n\n"
        f"| {proto} feature | Wrappers |\n| --- | --- |\n"
        f"{tally('features')}\n\n"
        f"| Document outside INET's {proto} catalogs | Wrappers |\n| --- | --- |\n"
        f"{tally('documents')}\n\n"
        "| Linux socket interface, no standard | Wrappers |\n| --- | --- |\n"
        f"{tally('linux')}\n\n"
        "## Counts\n\n"
        f"- wrappers: **{counts['wrappers']}**, of which {counts['fail']} expect `FAIL` because INET\n"
        "  cannot run the script\n"
        f"- scripts without a wrapper: **{len(excluded)}**, listed below\n\n"
        "## Scripts without a wrapper\n\n"
        "A script that no longer passes on Linux (kernel drift) states no Linux behavior, so a\n"
        "wrapper for it would prove nothing. The suite does not run a skipped script.\n\n"
        "| Script | Why | Detail |\n| --- | --- | --- |\n"
        f"{rows}\n"
    )


def cmd_gen_wrappers(args):
    into = os.path.abspath(args.into)
    if os.path.basename(into) != "protocol":
        sys.exit(f"--into must be INET's tests/protocol folder, not {into}")
    cfg = load_config()
    mapping = load_mapping()
    features = load_features()
    meta, linux_rows = read_linux_results()
    release = meta.get("kernel", "?")
    files, total, folders = {}, collections.Counter(), []
    for set_name, script_set in sorted(cfg["script_sets"].items()):
        folder = set_folder(script_set)
        folders.append(folder)
        excluded, entries, example = [], [], None
        counts = {"wrappers": 0, "fail": 0}
        for _, script_id, path in iter_scripts({"script_sets": {set_name: script_set}}):
            key = script_key(path)
            skip = (cfg.get("skips") or {}).get(key)
            if skip:
                excluded.append((key, "skipped", skip))
                continue
            drift = (cfg.get("kernel_drift") or {}).get(key)
            if drift:
                excluded.append((key, "kernel drift", drift))
                continue
            linux_row = linux_rows.get(key)
            if not linux_row or linux_row["verdict"] != "LINUX_PASS":
                excluded.append((key, "no passing Linux run",
                                 f"Linux {release}: {linux_row['verdict'] if linux_row else 'no result'}"))
                continue
            if linux_row["script_sha256"] != sha256_of(path):
                sys.exit(f"{key}: the script differs from the one Linux ran; run `make verify-scripts`")
            _, _, _, _, blocking = prepare_inet_run(script_id, path, mapping, preamble_sysctls(cfg, set_name))
            entry = exercised(features, key, script_id)
            entries.append(entry)
            files[key + ".test"] = wrapper_text(script_set, key, script_id, linux_row, blocking, entry, release)
            example = example or script_id
            counts["wrappers"] += 1
            counts["fail"] += 1 if blocking else 0
        files[os.path.join(folder, "README.md")] = wrappers_readme(
            set_name, script_set, folder, example, counts, excluded, entries, release)
        total.update(counts)
        total["excluded"] += len(excluded)

    # Only the folders of the script sets belong to the generator; INET's other tests, and the
    # work/ folders that its test runners make beside each test, stay as they are.
    present = {os.path.relpath(p, into)
               for folder in folders
               for p in glob.glob(os.path.join(into, folder, "**", "*.test"), recursive=True)
               if "/work/" not in p}
    stale = sorted(present - set(files))
    if args.check:
        wrong = [rel for rel, text in sorted(files.items())
                 if not os.path.exists(os.path.join(into, rel)) or open(os.path.join(into, rel)).read() != text]
        for rel in wrong:
            print(f"out of date: {rel}")
        for rel in stale:
            print(f"not generated: {rel}")
        print(f"{total['wrappers']} wrappers, {total['excluded']} scripts without one; "
              f"{len(wrong)} out of date, {len(stale)} not generated")
        sys.exit(1 if wrong or stale else 0)
    for rel, text in files.items():
        dst = os.path.join(into, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w") as f:
            f.write(text)
    for rel in stale:
        os.remove(os.path.join(into, rel))
    for folder in folders:
        for d, _, _ in sorted(os.walk(os.path.join(into, folder)), reverse=True):
            if not os.listdir(d):
                os.rmdir(d)
    print(f"wrote {total['wrappers']} wrappers ({total['fail']} expect FAIL) and "
          f"{len(folders)} README.md files into {into}; {total['excluded']} scripts without a wrapper; "
          f"removed {len(stale)} stale wrappers")


# ---------------------------------------------------------------------------
# The comparison: join the Linux results with the INET run's into the scoreboard.
# ---------------------------------------------------------------------------

def kernel_source_hint(category, src_root=""):
    """Which kernel source file to read when a script diverges.

    Paths are kernel-tree-relative; src_root (environment.kernel_source_root
    in scripts.yaml, optional) prefixes them with a local checkout when one is
    configured.
    """
    hint = PROTOCOL_RULES.SOURCE_HINTS.get(category, PROTOCOL_RULES.DEFAULT_SOURCE_HINT)
    prefix = os.path.join(src_root, "") if src_root else ""
    return ", ".join(f"{prefix}{f.strip()}" for f in hint.split(","))


def load_json_if_exists(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def combine_verdict(linux, inet, is_known_drift=False):
    """Combine the two runs' verdicts per the taxonomy: a Linux-side failure
    (LINUX_FAIL/LINUX_ERROR) always wins -- the script isn't a trustworthy contract on
    this kernel, regardless of what INET did.

    Such a failure splits in two, and the difference matters: KERNEL_DRIFT is a
    script whose expectations have been *investigated* and shown not to hold on
    this kernel (scripts.yaml's kernel_drift map records the mechanism per
    script), while LINUX_SUSPECT is everything else -- i.e. something we have
    not explained yet, most often a harness or environment problem worth
    chasing. Keeping them apart is what lets LINUX_SUSPECT read as an alarm
    rather than a backlog.
    """
    l_verdict = linux["verdict"] if linux else "LINUX_MISSING"
    i_verdict = inet["verdict"] if inet else "INET_MISSING"
    if l_verdict in ("LINUX_FAIL", "LINUX_ERROR", "LINUX_MISSING"):
        return "KERNEL_DRIFT" if is_known_drift else "LINUX_SUSPECT"
    if i_verdict == "INET_DIALECT":
        return "DIALECT_GAP"
    if i_verdict == "INET_UNSUPPORTED_CONFIG":
        return "UNSUPPORTED_FEATURE"
    if i_verdict == "INET_CRASH":
        return "CRASH"
    if i_verdict == "INET_DIVERGE":
        return "DIVERGENCE"
    if i_verdict == "INET_STALLED":
        # The script ran out of events without error: an expected outbound
        # packet never arrived. Same class as a divergence -- the DUT failed
        # to produce scripted behavior -- just detected by omission.
        return "DIVERGENCE"
    if i_verdict == "INET_PASS":
        return "MATCH"
    return "INET_MISSING"


def cmd_compare(args):
    cfg = load_config()
    meta, linux_rows = read_linux_results()
    cfg["environment"]["kernel_release"] = meta.get("kernel", "?")
    inet_dir = os.path.join(SUITE_DIR, "out", "inet_results")
    out_dir = os.path.join(SUITE_DIR, "out")
    os.makedirs(out_dir, exist_ok=True)

    drift_map = cfg.get("kernel_drift") or {}
    stale_drift = []
    scripts = list(iter_scripts(cfg, args.filter))
    records = []
    for set_name, script_id, path in scripts:
        skip_key = script_key(path)
        if skip_key in (cfg.get("skips") or {}):
            continue
        fname = script_key_to_filename(skip_key)
        linux = linux_rows.get(skip_key)
        inet = load_json_if_exists(os.path.join(inet_dir, fname))
        category = PROTOCOL_RULES.categorize(script_id)
        combined = combine_verdict(linux, inet, skip_key in drift_map)
        # A drift entry that starts passing is stale bookkeeping, not a result:
        # say so rather than silently keeping the script off the scoreboard.
        if skip_key in drift_map and linux and linux["verdict"] == "LINUX_PASS":
            stale_drift.append(skip_key)
        record = {
            "id": skip_key, "script": script_id, "set": set_name, "category": category,
            "combined_verdict": combined,
            "linux_verdict": linux["verdict"] if linux else None,
            "inet_verdict": inet["verdict"] if inet else None,
            "linux": linux, "inet": inet,
        }
        if combined == "DIVERGENCE":
            record["kernel_source_hint"] = kernel_source_hint(
                category, cfg["environment"].get("kernel_source_root", ""))
        records.append(record)

    report_json_path = os.path.join(out_dir, "report.json")
    with open(report_json_path, "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")

    md = render_report_md(records, cfg)
    report_md_path = os.path.join(out_dir, "report.md")
    with open(report_md_path, "w") as f:
        f.write(md)

    print(f"wrote {report_json_path}")
    print(f"wrote {report_md_path}")
    counts = {}
    for r in records:
        counts[r["combined_verdict"]] = counts.get(r["combined_verdict"], 0) + 1
    print("\n=== combined scoreboard ===")
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict}: {n}")
    if stale_drift:
        print("\nstale kernel_drift entries -- the Linux run now PASSES these, so they are being\n"
              "withheld from the scoreboard for no reason. Drop them from scripts.yaml:")
        for key in stale_drift:
            print(f"  {key}")


def render_report_md(records, cfg):
    lines = []
    lines.append(f"# {PROTOCOL.upper()} scoreboard: INET against Linux\n")
    lines.append(f"Kernel: `{cfg['environment']['kernel_release']}`  ")
    lines.append(f"INET commit: `{cfg['environment']['inet_commit'][:12]}`  ")
    lines.append(f"INETGPL commit: `{cfg['environment']['inetgpl_commit'][:12]}`  ")
    lines.append(f"Scripts evaluated: {len(records)}\n")

    counts = {}
    for r in records:
        counts[r["combined_verdict"]] = counts.get(r["combined_verdict"], 0) + 1
    lines.append("## Headline\n")
    lines.append("| Verdict | Count | Share |")
    lines.append("|---|---|---|")
    total = len(records) or 1
    for verdict, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {verdict} | {n} | {100 * n / total:.0f}% |")
    lines.append("")

    lines.append("## By category\n")
    lines.append("This is the \"state of INET TCP vs Linux\" view: which parts of the "
                  "protocol are MATCH-verified, which genuinely diverge, and which never "
                  "even run (dialect gap / crash / unsupported config).\n")
    by_cat = {}
    for r in records:
        by_cat.setdefault(r["category"], {}).setdefault(r["combined_verdict"], 0)
        by_cat[r["category"]][r["combined_verdict"]] += 1
    all_verdicts = ["MATCH", "DIVERGENCE", "CRASH", "DIALECT_GAP", "UNSUPPORTED_FEATURE",
                    "KERNEL_DRIFT", "LINUX_SUSPECT"]
    lines.append("| Category | " + " | ".join(all_verdicts) + " | Total |")
    lines.append("|---|" + "---|" * (len(all_verdicts) + 1))
    for cat in sorted(by_cat, key=lambda c: -sum(by_cat[c].values())):
        counts_row = by_cat[cat]
        total_cat = sum(counts_row.values())
        cells = [str(counts_row.get(v, "")) or "-" for v in all_verdicts]
        lines.append(f"| {cat} | " + " | ".join(cells) + f" | {total_cat} |")
    lines.append("")

    divergences = [r for r in records if r["combined_verdict"] == "DIVERGENCE"]
    if divergences:
        lines.append(f"## Divergences ({len(divergences)})\n")
        for r in divergences:
            leg_i_div = (r["inet"] or {}).get("divergence") or {}
            lines.append(f"### {r['id']}\n")
            lines.append(f"- kernel source hint: `{r.get('kernel_source_hint', '')}`")
            lines.append(f"- message: {leg_i_div.get('message', r['inet'].get('diagnostic') if r['inet'] else '')}")
            unmapped = (r["inet"] or {}).get("unmapped_knobs") or []
            if unmapped:
                lines.append(f"- unmapped knobs (possible attribution): {', '.join(unmapped)}")
            lines.append("")

    unsupported = [r for r in records if r["combined_verdict"] == "UNSUPPORTED_FEATURE"]
    if unsupported:
        by_reason = {}
        for r in unsupported:
            reason = (r["inet"] or {}).get("diagnostic") or "(unknown)"
            by_reason.setdefault(reason, []).append(f"{r['id']}")
        lines.append(f"## Unsupported config ({len(unsupported)})\n")
        for reason, scripts in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- **{reason}** ({len(scripts)}): {', '.join(scripts[:5])}"
                         + (f", ... +{len(scripts) - 5} more" if len(scripts) > 5 else ""))
        lines.append("")

    dialect = [r for r in records if r["combined_verdict"] == "DIALECT_GAP"]
    if dialect:
        by_construct = {}
        for r in dialect:
            detail = (r["inet"] or {}).get("diagnostic") or "(unknown)"
            m = re.search(r"parse error at '(.*?)':", detail)
            key = m.group(1) if m else detail[:40]
            by_construct.setdefault(key, []).append(f"{r['id']}")
        lines.append(f"## Dialect gap ({len(dialect)})\n")
        for construct, scripts in sorted(by_construct.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- **{construct!r}** ({len(scripts)}): {', '.join(scripts[:5])}"
                         + (f", ... +{len(scripts) - 5} more" if len(scripts) > 5 else ""))
        lines.append("")

    crashes = [r for r in records if r["combined_verdict"] == "CRASH"]
    if crashes:
        lines.append(f"## Crashes ({len(crashes)})\n")
        for r in crashes:
            diag = (r["inet"] or {}).get("diagnostic") or ""
            lines.append(f"- **{r['id']}**: {diag[:200]}")
        lines.append("")

    drift = [r for r in records if r["combined_verdict"] == "KERNEL_DRIFT"]
    if drift:
        lines.append(f"## Kernel drift ({len(drift)}, excluded from MATCH/DIVERGENCE)\n")
        lines.append("The Linux run worked and the kernel disagreed with the script: the "
                     "script pins behavior this kernel no longer has. Investigated one by "
                     "one; the mechanism for each is recorded in scripts.yaml's "
                     "`kernel_drift` map. Nothing on the harness side recovers these -- "
                     "re-check them after a kernel upgrade or a re-pin of the scripts.\n")
        for r in drift:
            reason = (cfg.get("kernel_drift") or {}).get(f"{r['id']}", "")
            lines.append(f"- **{r['id']}** (linux={r['linux_verdict']}): {reason}")
        lines.append("")

    suspects = [r for r in records if r["combined_verdict"] == "LINUX_SUSPECT"]
    if suspects:
        lines.append(f"## Linux-suspect ({len(suspects)}, excluded from MATCH/DIVERGENCE)\n")
        lines.append("The Linux run itself did not pass, erred, or has no "
                     "result -- these scripts are not a trustworthy contract on this kernel "
                     "and are not counted toward INET's pass/fail.\n")
        for r in suspects:
            lines.append(f"- **{r['id']}**: linux={r['linux_verdict']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def cmd_run(args):
    cmd_linux(args)
    cmd_inet(args)
    cmd_compare(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_linux = sub.add_parser("linux", help="run the scripts on the Linux kernel and record linux-results.csv")
    p_linux.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_linux.add_argument("--tolerance-usecs", dest="tolerance_usecs", default=DEFAULT_TOLERANCE_USECS)
    p_linux.add_argument("--privileged", action="store_true", help="run packetdrill as real root via `sudo -n unshare -n` instead of unprivileged `unshare -r -n`. Needed by the scripts that write a module parameter (cubic hystart), flush tcp_metrics, or lock a multi-megabyte buffer. Module parameters are snapshotted and restored around the run.")
    p_linux.set_defaults(func=cmd_linux)

    p_pre = sub.add_parser("preprocess", help="dry-run the preprocessor and the sysctl translation over the scripts")
    p_pre.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_pre.add_argument("--verbose", action="store_true")
    p_pre.set_defaults(func=cmd_preprocess)

    p_inet = sub.add_parser("inet", help="run the scripts in INET's PacketDrillApp and record the results")
    p_inet.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_inet.set_defaults(func=cmd_inet)

    p_one = sub.add_parser("inet-one",
                           help="run one script in INET, print a verdict line, exit 0 only on a pass")
    p_one.add_argument("script", help="the script's path below tests/protocol, without .pkt, e.g. tcp/packetdrill/fast_retransmit/fr-4pkt-sack")
    p_one.set_defaults(func=cmd_inet_one)

    p_gen = sub.add_parser("gen-wrappers",
                           help="write INET's wrapper .test files for the scripts, or --check them")
    p_gen.add_argument("--into", required=True,
                       help="INET's tests/protocol folder; the wrappers go to the script sets' folders in it")
    p_gen.add_argument("--check", action="store_true", help="compare instead of writing; exit 1 if out of date")
    p_gen.set_defaults(func=cmd_gen_wrappers)

    p_compare = sub.add_parser("compare", help="join the Linux and INET results into out/report.json and out/report.md")
    p_compare.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_compare.set_defaults(func=cmd_compare)

    p_verify = sub.add_parser("verify-scripts",
                              help="check the scripts against linux-results.csv's hashes, and the helper paths of the Linux run")
    p_verify.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_verify.set_defaults(func=cmd_verify_scripts)

    p_run = sub.add_parser("run", help="run linux + inet + compare over the scripts")
    p_run.add_argument("--filter", help="regex over the script id (its path below tests/protocol) to restrict scripts")
    p_run.add_argument("--tolerance-usecs", dest="tolerance_usecs", default=DEFAULT_TOLERANCE_USECS)
    p_run.add_argument("--privileged", action="store_true", help="run packetdrill as real root via `sudo -n unshare -n` instead of unprivileged `unshare -r -n`. Needed by the scripts that write a module parameter (cubic hystart), flush tcp_metrics, or lock a multi-megabyte buffer. Module parameters are snapshotted and restored around the run.")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
