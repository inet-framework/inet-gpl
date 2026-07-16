#!/usr/bin/env python3
"""TCP oracle test framework: run packetdrill scripts against both the real
Linux kernel (leg L) and INET's PacketDrillApp (leg I), then compare.

See tests/oracle/README.md for usage. Single entry point; subcommands below.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time

import yaml

ORACLE_DIR = os.path.dirname(os.path.abspath(__file__))
INETGPL_ROOT = os.path.dirname(os.path.dirname(ORACLE_DIR))

# -D symbols referenced across both corpora's TCP scripts (union of
# gtests/net/packetdrill/run_all.py and the kernel selftest ksft_runner.sh
# ipv4 flag blocks). Extra unused -D definitions are harmless to packetdrill.
IPV4_FLAGS = [
    "--ip_version=ipv4",
    "--local_ip=192.168.0.1",
    "--gateway_ip=192.168.0.1",
    "--netmask_ip=255.255.0.0",
    "--remote_ip=192.0.2.1",
    "-D", "TFO_COOKIE=3021b9d889017eeb",
    "-D", "TFO_COOKIE_ZERO=b7c12350a90dc8f5",
    "-D", "CMSG_LEVEL_IP=SOL_IP",
    "-D", "CMSG_TYPE_RECVERR=IP_RECVERR",
    "-D", "CODE=host_unreachable",
]

DEFAULT_TOLERANCE_USECS = "50000"
LEG_L_TIMEOUT_S = 60

ORACLE_EXE = os.path.join(ORACLE_DIR, "build", "out", "clang-debug", "oracle_exe_dbg")
LEG_I_TIMEOUT_S = 30
# PacketDrillApp never calls endSimulation() itself (confirmed by inspection:
# no call site in PacketDrillApp.cc) -- every run, including the 10 legacy
# tests known-good from M0, terminates by hitting this configured limit, not
# by the event queue naturally emptying. This is NORMAL, not a hang signal;
# see classify_inet_output(). Because OMNeT++ is discrete-event, jumping
# straight to a far-future "check the limit" self-message costs no real
# wall-clock time regardless of magnitude (verified empirically), so this can
# be generous -- it only needs to exceed any real script's scripted duration.
LEG_I_SIM_TIME_LIMIT = "300s"


def _live_commit(root_env_var):
    try:
        r = subprocess.run(["git", "-C", os.environ[root_env_var], "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def load_corpus_config():
    with open(os.path.join(ORACLE_DIR, "corpus.yaml")) as f:
        cfg = yaml.safe_load(f)
    # inet/inetgpl commits: read live from the checkouts actually being run
    # against, not corpus.yaml's (stale-prone) pinned values -- the 2026-07-13
    # status report caught the pinned hash misattributing a fresh run.
    for env_var, key in (("INET_ROOT", "inet_commit"), ("INETGPL_ROOT", "inetgpl_commit")):
        live = _live_commit(env_var)
        if live:
            cfg["environment"][key] = live
    return cfg


def load_mapping():
    path = os.path.join(ORACLE_DIR, "mapping.yaml")
    if not os.path.exists(path):
        return {"sysctl": {}, "option": {}, "ignore": [], "required": []}
    with open(path) as f:
        return yaml.safe_load(f)


def iter_corpus_scripts(cfg, filter_re=None):
    """Yield (corpus_name, script_id, abspath) for every .pkt in the pinned corpora.

    script_id is the relative path (no .pkt suffix) inside the corpus subdir,
    e.g. "tcp_basic_client" or "fast_retransmit/fr-4pkt".
    """
    pattern = re.compile(filter_re) if filter_re else None
    for corpus_name, corpus in sorted(cfg["corpora"].items()):
        root = os.path.join(corpus["path"], corpus["subdir"])
        for path in sorted(glob.glob(os.path.join(root, "**", "*.pkt"), recursive=True)):
            script_id = os.path.relpath(path, root)[: -len(".pkt")]
            key = f"{corpus_name}:{script_id}"
            if pattern and not pattern.search(key):
                continue
            yield corpus_name, script_id, path


def script_key_to_filename(corpus_name, script_id):
    return f"{corpus_name}__{script_id.replace('/', '__')}.json"


def sha256_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


# ---------------------------------------------------------------------------
# Leg L: run the real Linux kernel via upstream packetdrill, unprivileged.
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


def run_leg_linux(script_path, tolerance_usecs=DEFAULT_TOLERANCE_USECS):
    """Run one script against the real kernel, unprivileged, in a fresh netns.

    Recipe proven in recon: `ulimit -s 2048` avoids an mlockall()/RLIMIT_MEMLOCK
    conflict (packetdrill mlockall()s itself; the default 8 MB thread stack blows
    the 8 MB memlock hard limit under an unprivileged user namespace). Do not
    "fix" this by zeroing memlock instead -- packetdrill aborts if mlockall fails.
    cwd is the script's own directory so its backtick init scripts (e.g.
    `./defaults.sh`, `../common/defaults.sh`) resolve their relative paths.
    """
    script_dir = os.path.dirname(script_path)
    script_name = os.path.basename(script_path)
    cmd = ["packetdrill"] + IPV4_FLAGS + [f"--tolerance_usecs={tolerance_usecs}", script_name]
    inner = "ip link set lo up; ulimit -s 2048; " + shlex.join(cmd)
    full_cmd = ["unshare", "-r", "-n", "sh", "-c", inner]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            full_cmd, cwd=script_dir, capture_output=True, text=True,
            timeout=LEG_L_TIMEOUT_S,
        )
        duration = time.monotonic() - start
    except subprocess.TimeoutExpired:
        return {
            "verdict": "L_ERROR",
            "duration_s": LEG_L_TIMEOUT_S,
            "diagnostic": f"timed out after {LEG_L_TIMEOUT_S}s",
            "divergence": None,
        }

    output = proc.stdout + proc.stderr
    if proc.returncode == 0:
        return {"verdict": "L_PASS", "duration_s": duration, "diagnostic": None, "divergence": None}

    divergence = parse_linux_diagnostic(output)
    if divergence is not None:
        return {
            "verdict": "L_FAIL", "duration_s": duration,
            "diagnostic": divergence["message"], "divergence": divergence,
        }
    # Nonzero exit with no recognized field-diff pattern: infra/harness problem
    # (e.g. init script failure, unsupported syscall) rather than a genuine
    # protocol divergence -- keep it separate so it doesn't pollute DIVERGENCE stats.
    return {
        "verdict": "L_ERROR", "duration_s": duration,
        "diagnostic": output.strip()[-2000:], "divergence": None,
    }


def cmd_linux(args):
    cfg = load_corpus_config()
    kernel_release = cfg["environment"]["kernel_release"]
    golden_dir = os.path.join(ORACLE_DIR, "golden", kernel_release)
    os.makedirs(golden_dir, exist_ok=True)

    scripts = list(iter_corpus_scripts(cfg, args.filter))
    print(f"Running leg L (Linux) over {len(scripts)} scripts, kernel {kernel_release}...")
    counts = {}
    for i, (corpus_name, script_id, path) in enumerate(scripts, 1):
        skip_key = f"{corpus_name}:{script_id}"
        if skip_key in (cfg.get("skips") or {}):
            continue
        result = run_leg_linux(path, args.tolerance_usecs)
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        record = {
            "script": script_id, "corpus": corpus_name,
            "script_sha256": sha256_of(path), "leg": "linux",
            "verdict": result["verdict"],
            "runner": {
                "kernel": kernel_release,
                "packetdrill": cfg["environment"]["packetdrill_binary"],
                "inet_commit": None, "inetgpl_commit": None,
            },
            "duration_s": round(result["duration_s"], 3),
            "diagnostic": result["diagnostic"],
            "divergence": result["divergence"],
        }
        out_path = os.path.join(golden_dir, script_key_to_filename(corpus_name, script_id))
        with open(out_path, "w") as f:
            json.dump(record, f, indent=2)
            f.write("\n")
        print(f"  [{i}/{len(scripts)}] {corpus_name}:{script_id}: {result['verdict']}")

    print("\n=== leg L summary ===")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict}: {n}")
    print(f"golden results written to {golden_dir}")


# ---------------------------------------------------------------------------
# Preprocessing: strip constructs the INET-fork parser can't read at all
# (backtick shell blocks, leading --option lines), resolve them to a sysctl/
# option set, and translate that set into INET ini overrides via mapping.yaml.
# ---------------------------------------------------------------------------

BACKTICK_RE = re.compile(r"(?m)^[^\n`]*`([^`]*)`[^\n]*\n?")
OPTION_LINE_RE = re.compile(r"(?m)^[ \t]*(--[a-zA-Z_][a-zA-Z_0-9]*(?:=\S+)?)[ \t]*(?://.*)?$")
SYSCTL_LINE_RE = re.compile(r"^sysctl\s+-q\s+(.*)$")
# The corpus's other sysctl mechanism: a helper script that pokes /proc/sys
# directly, e.g. `../../common/set_sysctls.py /proc/sys/net/ipv4/tcp_timestamps=0
# /proc/sys/net/ipv4/tcp_ecn=1`. Same key=value assignments as `sysctl -q`, but
# the keys are /proc/sys/ paths (stripped below). 59 corpus scripts use it, 32
# to set tcp_timestamps=0 -- without this they kept INET's default TS on and
# emitted an extra SYN option.
SET_SYSCTLS_RE = re.compile(r"set_sysctls\.py\s+(.+)$")
SYSCTL_ASSIGN_RE = re.compile(r'([a-zA-Z0-9_./]+)=("(?:[^"\\]|\\.)*"|\S+)')
PROC_SYS_PREFIX_RE = re.compile(r"^/?proc/sys/")


def preprocess_script(text, mapping):
    """Strip backtick blocks and leading --option lines; resolve backtick
    blocks to a sysctl dict via mapping['known_preambles'] (exact match) or a
    best-effort line-by-line `sysctl -q k=v [k2=v2 ...]` scan otherwise.

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

    known_preambles = mapping.get("known_preambles", [])
    for content in stripped["backtick_blocks"]:
        # A preamble (defaults.sh) may be FOLLOWED by explicit sysctl lines in
        # the same backtick block (the accecn corpus's usual shape). Match the
        # preamble against the first line only, apply its preset, then
        # line-scan the rest so explicit sysctls layer on top of (and
        # override) the preset -- previously a whole-content anchored match
        # dropped the preset entirely for such mixed blocks.
        lines = content.splitlines()
        rest = lines
        for kp in known_preambles:
            if lines and re.match(kp["match"], lines[0].strip()):
                stripped["sysctls"].update(kp["sysctls"])
                rest = lines[1:]
                break
        for line in rest:
            line = line.strip()
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
    I_UNSUPPORTED_CONFIG instead of running it.
    """
    ini = {}
    unmapped = []
    blocking = []
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
            ini[spec["ini"]] = val

    return ini, unmapped, blocking


def cmd_preprocess(args):
    """Dry-run helper (used by M2 acceptance + debugging): preprocess every
    matched script and report unmapped-knob / blocking-config statistics
    without running anything.
    """
    cfg = load_corpus_config()
    mapping = load_mapping()
    scripts = list(iter_corpus_scripts(cfg, args.filter))
    n_ok, n_blocked = 0, 0
    unmapped_counter = {}
    for corpus_name, script_id, path in scripts:
        text = open(path, encoding="utf-8", errors="replace").read()
        _, stripped = preprocess_script(text, mapping)
        _, unmapped, blocking = translate_to_ini(stripped, mapping)
        for u in unmapped:
            key = u.split("=", 1)[0]
            unmapped_counter[key] = unmapped_counter.get(key, 0) + 1
        if blocking:
            n_blocked += 1
            if args.verbose:
                print(f"BLOCKED {corpus_name}:{script_id}: {blocking}")
        else:
            n_ok += 1
    print(f"\npreprocessed {len(scripts)} scripts: {n_ok} translatable, {n_blocked} blocked")
    print("\nunmapped knob frequency (informational, non-blocking unless noted above):")
    for key, n in sorted(unmapped_counter.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {key}")


# ---------------------------------------------------------------------------
# Leg I: run the preprocessed script through INET's PacketDrillApp.
# ---------------------------------------------------------------------------

DIALECT_ERROR_RE = re.compile(r"parse error at '(?P<token>.*?)'|Error parsing the script")
DIVERGENCE_RE_INET = re.compile(r"Packetdrill error:\s*(?P<message>.*)")


def require_env():
    for var in ("INET_ROOT", "INETGPL_ROOT"):
        if not os.environ.get(var):
            sys.exit(
                f"{var} is not set. Run:\n"
                f"  cd $INET_ROOT && source setenv -q && cd $INETGPL_ROOT && source setenv -q\n"
                f"(both, in this order, in the same shell) before invoking oracle.py."
            )
    if not os.path.exists(ORACLE_EXE):
        sys.exit(
            f"{ORACLE_EXE} not found. Build it once:\n"
            f"  cd tests/oracle/build && opp_makemake -f --deep -lINET_dbg -lINETGPL_dbg "
            f"-L$INET_ROOT/src -L$INETGPL_ROOT/src -P . -I$INET_ROOT/src -I$INETGPL_ROOT/src "
            f"-o oracle_exe && make MODE=debug"
        )


def classify_inet_output(output, returncode, blocking_reasons):
    """Classify leg-I output per the taxonomy in the plan (order matters:
    dialect check before config-block check before crash check before
    divergence, since a dialect failure's log also often contains generic
    <!> Error noise that would otherwise misclassify as I_CRASH).

    Reaching "Simulation time limit reached" is NOT a failure signal here --
    PacketDrillApp never calls endSimulation() itself, so hitting the
    configured limit is how every run ends, success or not (see
    LEG_I_SIM_TIME_LIMIT). This mirrors the pass/fail discipline the 10
    legacy packetdrill tests already use (tests/packetdrill/tcp/*.test:
    `%not-contains: test.out / Packetdrill error:`): absence of a
    "Packetdrill error:" string (and absence of any other unrelated <!>
    Error) is what PASS means, not how the run terminated.
    """
    if blocking_reasons:
        return "I_UNSUPPORTED_CONFIG", "; ".join(blocking_reasons)
    m = DIALECT_ERROR_RE.search(output)
    if m:
        detail = m.group(0)
        return "I_DIALECT", detail
    m = DIVERGENCE_RE_INET.search(output)
    if m:
        return "I_DIVERGE", m.group("message").strip()
    generic_errors = [
        l for l in output.splitlines()
        if l.strip().startswith("<!>") and "Simulation time limit reached" not in l
    ]
    if returncode != 0 or generic_errors:
        return "I_CRASH", (generic_errors[0] if generic_errors else output.strip()[-500:])
    return "I_PASS", None


def extract_inet_divergence_context(output):
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "Packetdrill error:" in line:
            return {
                "script_line": None,
                "message": line.split("Packetdrill error:", 1)[1].strip(),
                "expected_packet": None,
                "actual_packet": None,
                "context_log": lines[max(0, i - 30): i + 1],
            }
    return None


def run_leg_inet(corpus_name, script_id, path, mapping, preproc_dir):
    require_env()
    text = open(path, encoding="utf-8", errors="replace").read()
    clean_text, stripped = preprocess_script(text, mapping)
    ini_overrides, unmapped, blocking = translate_to_ini(stripped, mapping)

    # A listener that opts into server Fast Open via setsockopt(TCP_FASTOPEN)
    # accepts TFO SYN data regardless of the sysctl's WO_SOCKOPT bits. INET has
    # no per-listener TFO opt-in (fastopenServerEnabled is module-wide), so treat
    # the presence of that setsockopt as enabling the server side -- complementing
    # the tcp_fastopen 0x400 (accept-on-any-listener) mapping. Without this, a
    # setsockopt-opt-in listener under e.g. tcp_fastopen=0x3 would wrongly reject
    # the SYN data; without the mapping side, a non-opt-in listener under
    # tcp_fastopen=2 would wrongly accept it.
    if re.search(r"setsockopt\([^)]*TCP_FASTOPEN\b(?!_CONNECT)", clean_text):
        ini_overrides["**.tcp.fastopenServerEnabled"] = "true"

    pp_name = f"{corpus_name}__{script_id.replace('/', '__')}.pkt"
    pp_path = os.path.join(preproc_dir, pp_name)
    os.makedirs(preproc_dir, exist_ok=True)
    with open(pp_path, "w") as f:
        f.write(clean_text)

    result_common = {
        "stripped_preamble": stripped,
        "ini_overrides": ini_overrides,
        "unmapped_knobs": unmapped,
    }

    if blocking:
        return {
            "verdict": "I_UNSUPPORTED_CONFIG", "duration_s": 0.0,
            "diagnostic": "; ".join(blocking), "divergence": None,
            **result_common,
        }

    ned_path = f"{os.environ['INET_ROOT']}/src;{os.environ['INETGPL_ROOT']}/src;{ORACLE_DIR}/ned"
    cmd = [
        ORACLE_EXE, "-u", "Cmdenv", "-f", os.path.join(ORACLE_DIR, "ini", "base.ini"),
        "-n", ned_path, "--cmdenv-interactive=false",
        f'--**.scriptFile="{pp_path}"',
        f"--sim-time-limit={LEG_I_SIM_TIME_LIMIT}",
    ]
    for key, val in ini_overrides.items():
        cmd.append(f"--{key}={val}")

    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=ORACLE_DIR, capture_output=True, text=True, timeout=LEG_I_TIMEOUT_S)
        duration = time.monotonic() - start
        output = proc.stdout + proc.stderr
        verdict, detail = classify_inet_output(output, proc.returncode, [])
    except subprocess.TimeoutExpired as e:
        duration = LEG_I_TIMEOUT_S
        output = (e.stdout or "") + (e.stderr or "")
        verdict, detail = "I_CRASH", f"timed out after {LEG_I_TIMEOUT_S}s"

    divergence = extract_inet_divergence_context(output) if verdict == "I_DIVERGE" else None
    return {
        "verdict": verdict, "duration_s": round(duration, 3),
        "diagnostic": detail, "divergence": divergence,
        **result_common,
    }


def cmd_inet(args):
    require_env()
    cfg = load_corpus_config()
    mapping = load_mapping()
    preproc_dir = os.path.join(ORACLE_DIR, "out", "preprocessed")
    results_dir = os.path.join(ORACLE_DIR, "out", "inet_results")
    os.makedirs(results_dir, exist_ok=True)

    scripts = list(iter_corpus_scripts(cfg, args.filter))
    print(f"Running leg I (INET) over {len(scripts)} scripts...")
    counts = {}
    for i, (corpus_name, script_id, path) in enumerate(scripts, 1):
        skip_key = f"{corpus_name}:{script_id}"
        if skip_key in (cfg.get("skips") or {}):
            continue
        result = run_leg_inet(corpus_name, script_id, path, mapping, preproc_dir)
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        record = {
            "script": script_id, "corpus": corpus_name,
            "script_sha256": sha256_of(path), "leg": "inet",
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
        out_path = os.path.join(results_dir, script_key_to_filename(corpus_name, script_id))
        with open(out_path, "w") as f:
            json.dump(record, f, indent=2)
            f.write("\n")
        print(f"  [{i}/{len(scripts)}] {corpus_name}:{script_id}: {result['verdict']}")

    print("\n=== leg I summary ===")
    for verdict, n in sorted(counts.items()):
        print(f"  {verdict}: {n}")
    print(f"results written to {results_dir}")


# ---------------------------------------------------------------------------
# Comparator: join leg-L golden results with leg-I results into the scoreboard.
# ---------------------------------------------------------------------------

# Multi-word category prefixes that would otherwise be truncated by a naive
# first-underscore-token split of the flat kernel-corpus filenames (e.g.
# "tcp_fast_recovery_prr-ss-...pkt" must categorize as "fast_recovery", not
# "fast"). Matched longest-first. gtests corpus scripts categorize by their
# own subdirectory name instead (unambiguous).
KNOWN_MULTIWORD_CATEGORIES = sorted([
    "fast_recovery", "fast_retransmit", "cwnd_moderation", "limited_transmit",
    "syscall_bad_arg", "notsent_lowat", "user_timeout", "ts_recent", "tcp_info",
    "rcv_zero_wnd", "slow_start", "mtu_probe", "mtu-probe",
], key=len, reverse=True)

KERNEL_SOURCE_HINTS = {
    "fastopen": "net/ipv4/tcp_fastopen.c",
    "fast_recovery": "net/ipv4/tcp_input.c, net/ipv4/tcp_recovery.c",
    "fast_retransmit": "net/ipv4/tcp_input.c, net/ipv4/tcp_recovery.c",
    "sack": "net/ipv4/tcp_input.c, net/ipv4/tcp_recovery.c",
    "limited_transmit": "net/ipv4/tcp_input.c, net/ipv4/tcp_recovery.c",
    "cwnd_moderation": "net/ipv4/tcp_input.c, net/ipv4/tcp_cong.c",
    "cubic": "net/ipv4/tcp_cubic.c, net/ipv4/tcp_cong.c",
    "slow_start": "net/ipv4/tcp_cong.c, net/ipv4/tcp_input.c",
    "user_timeout": "net/ipv4/tcp_timer.c",
    "ts_recent": "net/ipv4/tcp_input.c",
    "rto": "net/ipv4/tcp_timer.c",
    "nagle": "net/ipv4/tcp_output.c",
    "close": "net/ipv4/tcp.c, net/ipv4/tcp_output.c",
    "shutdown": "net/ipv4/tcp.c",
    "blocking": "net/ipv4/tcp.c",
    "accecn": "net/ipv4/tcp_input.c, net/ipv4/tcp_output.c",
    "ecn": "net/ipv4/tcp_input.c, net/ipv4/tcp_output.c",
    "zerocopy": "net/ipv4/tcp.c",
    "syncookies": "net/ipv4/syncookies.c",
    "md5": "net/ipv4/tcp_ipv4.c",
    "mss": "net/ipv4/tcp_output.c",
    "mtu_probe": "net/ipv4/tcp_input.c",
    "disorder": "net/ipv4/tcp_input.c",
    "rfc5961": "net/ipv4/tcp_input.c",
    "eor": "net/ipv4/tcp.c",
    "epoll": "net/ipv4/tcp.c",
    "gro": "net/ipv4/tcp_offload.c",
    "timestamping": "net/ipv4/tcp.c",
    "notsent_lowat": "net/ipv4/tcp.c",
    "validate": "net/ipv4/tcp_input.c",
    "tcp_info": "net/ipv4/tcp.c",
    "syscall_bad_arg": "net/ipv4/tcp.c",
    "sendfile": "net/ipv4/tcp.c",
    "splice": "net/ipv4/tcp.c",
    "inq": "net/ipv4/tcp.c",
    "ioctl": "net/ipv4/tcp.c",
    "dsack": "net/ipv4/tcp_input.c",
    "ooo": "net/ipv4/tcp_input.c",
    "basic": "net/ipv4/tcp_input.c, net/ipv4/tcp_output.c",
}
DEFAULT_KERNEL_SOURCE_HINT = "net/ipv4/tcp_input.c"
KERNEL_SRC_ROOT = "~/w/kernel/linux-7.2-rc2/"


def categorize(script_id):
    if "/" in script_id:
        return script_id.split("/", 1)[0]
    stem = script_id[len("tcp_"):] if script_id.startswith("tcp_") else script_id
    for cat in KNOWN_MULTIWORD_CATEGORIES:
        if stem.startswith(cat):
            return cat
    return stem.split("_")[0].split("-")[0]


def kernel_source_hint(category):
    hint = KERNEL_SOURCE_HINTS.get(category, DEFAULT_KERNEL_SOURCE_HINT)
    return ", ".join(f"{KERNEL_SRC_ROOT}{f.strip()}" for f in hint.split(","))


def load_json_if_exists(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def combine_verdict(leg_l, leg_i):
    """Combine leg-L/leg-I verdicts per the taxonomy: an oracle-side failure
    (L_FAIL/L_ERROR) always wins -- the script isn't a trustworthy contract on
    this kernel, regardless of what INET did."""
    l_verdict = leg_l["verdict"] if leg_l else "L_MISSING"
    i_verdict = leg_i["verdict"] if leg_i else "I_MISSING"
    if l_verdict in ("L_FAIL", "L_ERROR", "L_MISSING"):
        return "ORACLE_SUSPECT"
    if i_verdict == "I_DIALECT":
        return "DIALECT_GAP"
    if i_verdict == "I_UNSUPPORTED_CONFIG":
        return "UNSUPPORTED_FEATURE"
    if i_verdict == "I_CRASH":
        return "CRASH"
    if i_verdict == "I_DIVERGE":
        return "DIVERGENCE"
    if i_verdict == "I_PASS":
        return "MATCH"
    return "I_MISSING"


def cmd_compare(args):
    cfg = load_corpus_config()
    kernel_release = cfg["environment"]["kernel_release"]
    golden_dir = os.path.join(ORACLE_DIR, "golden", kernel_release)
    inet_dir = os.path.join(ORACLE_DIR, "out", "inet_results")
    out_dir = os.path.join(ORACLE_DIR, "out")
    os.makedirs(out_dir, exist_ok=True)

    scripts = list(iter_corpus_scripts(cfg, args.filter))
    records = []
    for corpus_name, script_id, path in scripts:
        skip_key = f"{corpus_name}:{script_id}"
        if skip_key in (cfg.get("skips") or {}):
            continue
        fname = script_key_to_filename(corpus_name, script_id)
        leg_l = load_json_if_exists(os.path.join(golden_dir, fname))
        leg_i = load_json_if_exists(os.path.join(inet_dir, fname))
        category = categorize(script_id)
        combined = combine_verdict(leg_l, leg_i)
        record = {
            "script": script_id, "corpus": corpus_name, "category": category,
            "combined_verdict": combined,
            "leg_l_verdict": leg_l["verdict"] if leg_l else None,
            "leg_i_verdict": leg_i["verdict"] if leg_i else None,
            "leg_l": leg_l, "leg_i": leg_i,
        }
        if combined == "DIVERGENCE":
            record["kernel_source_hint"] = kernel_source_hint(category)
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


def render_report_md(records, cfg):
    lines = []
    lines.append("# TCP Oracle Scoreboard\n")
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
    all_verdicts = ["MATCH", "DIVERGENCE", "CRASH", "DIALECT_GAP", "UNSUPPORTED_FEATURE", "ORACLE_SUSPECT"]
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
            leg_i_div = (r["leg_i"] or {}).get("divergence") or {}
            lines.append(f"### {r['corpus']}:{r['script']}\n")
            lines.append(f"- kernel source hint: `{r.get('kernel_source_hint', '')}`")
            lines.append(f"- message: {leg_i_div.get('message', r['leg_i'].get('diagnostic') if r['leg_i'] else '')}")
            unmapped = (r["leg_i"] or {}).get("unmapped_knobs") or []
            if unmapped:
                lines.append(f"- unmapped knobs (possible attribution): {', '.join(unmapped)}")
            lines.append("")

    unsupported = [r for r in records if r["combined_verdict"] == "UNSUPPORTED_FEATURE"]
    if unsupported:
        by_reason = {}
        for r in unsupported:
            reason = (r["leg_i"] or {}).get("diagnostic") or "(unknown)"
            by_reason.setdefault(reason, []).append(f"{r['corpus']}:{r['script']}")
        lines.append(f"## Unsupported config ({len(unsupported)})\n")
        for reason, scripts in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- **{reason}** ({len(scripts)}): {', '.join(scripts[:5])}"
                         + (f", ... +{len(scripts) - 5} more" if len(scripts) > 5 else ""))
        lines.append("")

    dialect = [r for r in records if r["combined_verdict"] == "DIALECT_GAP"]
    if dialect:
        by_construct = {}
        for r in dialect:
            detail = (r["leg_i"] or {}).get("diagnostic") or "(unknown)"
            m = re.search(r"parse error at '(.*?)':", detail)
            key = m.group(1) if m else detail[:40]
            by_construct.setdefault(key, []).append(f"{r['corpus']}:{r['script']}")
        lines.append(f"## Dialect gap ({len(dialect)})\n")
        for construct, scripts in sorted(by_construct.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- **{construct!r}** ({len(scripts)}): {', '.join(scripts[:5])}"
                         + (f", ... +{len(scripts) - 5} more" if len(scripts) > 5 else ""))
        lines.append("")

    crashes = [r for r in records if r["combined_verdict"] == "CRASH"]
    if crashes:
        lines.append(f"## Crashes ({len(crashes)})\n")
        for r in crashes:
            diag = (r["leg_i"] or {}).get("diagnostic") or ""
            lines.append(f"- **{r['corpus']}:{r['script']}**: {diag[:200]}")
        lines.append("")

    suspects = [r for r in records if r["combined_verdict"] == "ORACLE_SUSPECT"]
    if suspects:
        lines.append(f"## Oracle-suspect ({len(suspects)}, excluded from MATCH/DIVERGENCE)\n")
        lines.append("Leg L (the real kernel) itself did not pass, erred, or has no golden "
                     "result -- these scripts are not a trustworthy contract on this kernel "
                     "and are not counted toward INET's pass/fail.\n")
        for r in suspects:
            lines.append(f"- **{r['corpus']}:{r['script']}**: leg_l={r['leg_l_verdict']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def cmd_run(args):
    cmd_linux(args)
    cmd_inet(args)
    cmd_compare(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_linux = sub.add_parser("linux", help="run leg L (Linux kernel) and record golden results")
    p_linux.add_argument("--filter", help="regex over 'corpus:script_id' to restrict scripts")
    p_linux.add_argument("--tolerance-usecs", dest="tolerance_usecs", default=DEFAULT_TOLERANCE_USECS)
    p_linux.set_defaults(func=cmd_linux)

    p_pre = sub.add_parser("preprocess", help="dry-run the preprocessor/mapping over the corpus")
    p_pre.add_argument("--filter", help="regex over 'corpus:script_id' to restrict scripts")
    p_pre.add_argument("--verbose", action="store_true")
    p_pre.set_defaults(func=cmd_preprocess)

    p_inet = sub.add_parser("inet", help="run leg I (INET PacketDrillApp) and record results")
    p_inet.add_argument("--filter", help="regex over 'corpus:script_id' to restrict scripts")
    p_inet.set_defaults(func=cmd_inet)

    p_compare = sub.add_parser("compare", help="join golden + INET results into report.json/report.md")
    p_compare.add_argument("--filter", help="regex over 'corpus:script_id' to restrict scripts")
    p_compare.set_defaults(func=cmd_compare)

    p_run = sub.add_parser("run", help="run linux + inet + compare over the corpus")
    p_run.add_argument("--filter", help="regex over 'corpus:script_id' to restrict scripts")
    p_run.add_argument("--tolerance-usecs", dest="tolerance_usecs", default=DEFAULT_TOLERANCE_USECS)
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
