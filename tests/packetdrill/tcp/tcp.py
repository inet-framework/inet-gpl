"""The rules of the TCP scripts that are TCP's own, for tests/packetdrill/suite.py.

suite.py loads <protocol>/<protocol>.py and uses:

  LINUX_FLAGS         the packetdrill flags and -D symbols of a Linux run
  MODULE_PARAM_DIRS   module parameter folders a privileged Linux run snapshots and restores
  translate_special(sysctls, ini)
                      the sysctls and pseudo-knobs whose translation into INET parameters
                      is not a plain entry of sysctls.yaml; pops the pseudo-knobs it handles
  adjust_inet_run(script_id, text, ini, blocking)
                      per-script changes of an INET run, decided from the script's text
  categorize(script_id)
                      the category of a script, by which the report groups the scripts
  SOURCE_HINTS, DEFAULT_SOURCE_HINT
                      the Linux source files to read when a script of a category diverges
"""
import re

# -D symbols referenced across both script sets (union of
# gtests/net/packetdrill/run_all.py and the kernel selftest ksft_runner.sh
# ipv4 flag blocks). Extra unused -D definitions are harmless to packetdrill.
LINUX_FLAGS = [
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

# Module parameters are NOT network-namespaced: a script that writes one (only
# the two cubic hystart tests do, and only in privileged mode can the write
# succeed) changes the behavior of every CUBIC connection on the host, and none
# of them restores what it changed. Snapshot the whole directory around a
# privileged run and put it back.
MODULE_PARAM_DIRS = ["/sys/module/tcp_cubic/parameters"]


def translate_special(sysctls, ini):
    # tcp_rmem is on the ignore list (no faithful static window translation),
    # but its MAX field DOES determine Linux's advertised window scale:
    # wscale = smallest k with (65535 << k) >= rmem_max (tcp_select_initial_window).
    # The scripts' Linux results pin exactly this (rmem max 15728640 -> wscale 8,
    # 33554432 -> wscale 10); base.ini's flat windowScalingFactor=8 mis-scales
    # the scripts that raise rmem. advertisedWindow stays untouched.
    rmem = sysctls.get("net.ipv4.tcp_rmem")
    if rmem:
        try:
            # tcp_rmem's MIDDLE value is the initial sk_rcvbuf (Linux socket(2)
            # default) -- the RECEIVE BUFFER capacity, distinct from the
            # advertised window. INET's receiveBufferSize decoupling lets a
            # large out-of-order flight be buffered like Linux does
            # (ooo-before-and-after-accept asserts SK_MEMINFO_RCVBUF==tcp_rmem[1]
            # and injects 99KB of OOO data against a 29200 advertised window).
            rmem_def = int(rmem.split()[1])
            ini["**.tcp.receiveBufferSize"] = f"{rmem_def}B"
        except (IndexError, ValueError):
            pass
        try:
            rmem_max_str = rmem.split()[2]
            # scripts write the max as shell arithmetic, e.g. $((32*1024*1024))
            am = re.fullmatch(r"\$\(\(([\d*+ ]+)\)\)", rmem_max_str)
            if am:
                rmem_max = 1
                for part in am.group(1).replace(" ", "").split("*"):
                    rmem_max *= int(part)
            else:
                rmem_max = int(rmem_max_str)
            k = 0
            while k < 14 and (65535 << k) < rmem_max:
                k += 1
            ini["**.tcp.windowScalingFactor"] = str(k)
        except (IndexError, ValueError):
            pass
    # device-MTU pseudo-knob from the preamble scanner: DUT advertises MTU-40
    tun_mtu = sysctls.pop("__tun_mtu", None)
    if tun_mtu:
        ini["**.tcp.mss"] = str(int(tun_mtu) - 40)
    # Route attributes. advmss is what the DUT announces AND -- together with the
    # route MTU, which gives the same number here -- what it sends; INET's single
    # `mss` parameter covers both. The route MTU is kept separately because RFC 4821
    # probing needs the ceiling even after the MSS has been pinned lower.
    route_advmss = sysctls.pop("__route_advmss", None)
    route_mtu = sysctls.pop("__route_mtu", None)
    route_initcwnd = sysctls.pop("__route_initcwnd", None)
    if route_advmss:
        ini["**.tcp.mss"] = route_advmss
    if route_mtu:
        ini["**.tcp.pathMtu"] = route_mtu
        if not route_advmss:
            ini["**.tcp.mss"] = str(int(route_mtu) - 40)
    if route_initcwnd:
        ini["**.tcp.initialCwnd"] = route_initcwnd


def adjust_inet_run(script_id, clean_text, ini_overrides, blocking):
    # A listener that opts into server Fast Open via setsockopt(TCP_FASTOPEN)
    # accepts TFO SYN data regardless of the sysctl's WO_SOCKOPT bits. INET has
    # no per-listener TFO opt-in (fastopenServerEnabled is module-wide), so treat
    # the presence of that setsockopt as enabling the server side -- complementing
    # the tcp_fastopen 0x400 (accept-on-any-listener) mapping. Without this, a
    # setsockopt-opt-in listener under e.g. tcp_fastopen=0x3 would wrongly reject
    # the SYN data; without the mapping side, a non-opt-in listener under
    # tcp_fastopen=2 would wrongly accept it.
    # ... but not when the setsockopt line is COMMENTED OUT (icmp-baseline
    # deliberately ships it commented: the listener must NOT be TFO-enabled,
    # and a spurious enable makes INET echo a fresh cookie on the SYN-ACK).
    uncommented_text = "\n".join(l for l in clean_text.splitlines() if not l.lstrip().startswith("//"))
    if re.search(r"setsockopt\([^)]*TCP_FASTOPEN\b(?!_CONNECT)", uncommented_text):
        ini_overrides["**.tcp.fastopenServerEnabled"] = "true"
    # Mid-script `tc qdisc` manipulation (e.g. user-timeout-probe installs a
    # zero-limit pfifo so every LOCAL transmit is dropped, exercising Linux's
    # TCP_RESOURCE_PROBE_INTERVAL local-congestion retries): there is no INET
    # analog for local-qdisc packet drops, and silently ignoring the command
    # produces a misleading DIVERGENCE for behavior the harness cannot model.
    if re.search(r"\btc qdisc\b", uncommented_text):
        blocking.append("mid-script tc qdisc manipulation (local-congestion drops not modeled)")

    # Explicit-read receive model (PacketDrillApp.explicitRead): these scripts'
    # behavior depends on GENUINE receive-buffer occupancy -- data arrives long
    # before (or without) the script reading it, and the window/acceptance/ack
    # decisions Linux makes hinge on the unread bytes held in the socket
    # buffer. The harness's default autoRead model drains data to the app
    # instantly and cannot express that; explicit-read keeps unread data in
    # TCP's receive queue like a real socket buffer. Opt-in per script: for
    # the rest of the scripts (prompt readers) the two models are equivalent
    # and autoRead avoids perturbing the long-validated read plumbing.
    EXPLICIT_READ_SCRIPTS = {
        "tcp_rcv_big_endseq",
        "tcp_rcv_neg_window",
        "tcp_rcv_wnd_shrink_allowed",
        "tcp_rcv_wnd_shrink_nomem",
        "tcp_ooo-before-and-after-accept",
    }
    if script_id.split("/")[-1] in EXPLICIT_READ_SCRIPTS:
        ini_overrides["**.tunApp[*].explicitRead"] = "true"


# Multi-word category prefixes that would otherwise be truncated by a naive
# first-underscore-token split of the flat file names of the Linux set (e.g.
# "tcp_fast_recovery_prr-ss-...pkt" must categorize as "fast_recovery", not
# "fast"). Matched longest-first. The packetdrill set's scripts categorize by their
# own subdirectory name instead (unambiguous).
KNOWN_MULTIWORD_CATEGORIES = sorted([
    "fast_recovery", "fast_retransmit", "cwnd_moderation", "limited_transmit",
    "syscall_bad_arg", "notsent_lowat", "user_timeout", "ts_recent", "tcp_info",
    "rcv_zero_wnd", "slow_start", "mtu_probe", "mtu-probe",
], key=len, reverse=True)

SOURCE_HINTS = {
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
DEFAULT_SOURCE_HINT = "net/ipv4/tcp_input.c"


def categorize(script_id):
    if "/" in script_id:
        return script_id.split("/", 1)[0]
    stem = script_id[len("tcp_"):] if script_id.startswith("tcp_") else script_id
    for cat in KNOWN_MULTIWORD_CATEGORIES:
        if stem.startswith(cat):
            return cat
    return stem.split("_")[0].split("-")[0]
