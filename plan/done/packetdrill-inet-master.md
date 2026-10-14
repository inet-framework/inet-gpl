# Run the packetdrill suite against INET master, with LinuxTcp

Status: **done** — the owner approved it on 2026-10-14; the INET repairs landed on INET master
`2424a1a865`.

- Branch `topic/packetdrill-inet-master`, on `inet-gpl` master `a0b22d2`.
- INET master `365c3941f7`: the TCP branch `topic/tcp-new-audit-fixes` landed there in the stages
  S1 to S20 of INET's `plan/done/tcp-staged-landing.md`.

## 1. The goal

inet-gpl builds against INET master, not against the TCP branch, and the TCP module of the
packetdrill host is `LinuxTcp`, INET's `Tcp` with the defaults of Linux 7.1. `tcp.ini` then keeps
only what the scripts set apart from stock Linux. The suite gives on master what it gives on the
TCP branch (303 MATCH, 12 KERNEL_DRIFT, 3 UNSUPPORTED), or each difference has a reason. INET's
protocol-test job, which builds inet-gpl master against the INET under test and runs the 306
packetdrill wrappers, then works on INET master.

## 2. What stands in the way

`PacketDrillApp` set five parameters of the `tcp` module at run time, which master does not mark
`@mutable`, because a socket option belongs to one socket, not to the module (INET D-4, D-66,
D-90): `advertisedWindow`, `windowScalingFactor`, `receiveBufferSize`, `receiveBufferLocked`
(master has no such parameter) and `synRetries`. Each script that sets SO_RCVBUF or TCP_SYNCNT,
and each `socket()`, stopped with "Setting the parameter is not allowed at run time": 49 crashes.

Master has a socket call for each: `TcpSocket::setAdvertisedWindow()`,
`TcpSocket::setReceiveBufferSize()`, which also locks the buffer, and `TcpSocket::setSynRetries()`.
They travel in the open command of the socket. `TcpSocket::renewSocket()` keeps them, so the app
resets them at each `socket()`.

## 3. The steps

| Step | Commit | What |
| --- | --- | --- |
| 1 ✅ | PacketDrillApp: SO_RCVBUF and TCP_SYNCNT as socket calls of INET | the five run-time writes go |
| 2 ✅ | (INET) the repairs of section 5, on the INET branch `topic/tcp-packetdrill-repairs` | see section 5 |
| 3 ✅ | tests/packetdrill: the host runs LinuxTcp | `tcp.ini` selects `LinuxTcp` and keeps only `advertisedWindow` |
| 4 ✅ | the record | the suite on master, the wrappers of INET |

## 4. The suite on master

Measured on 2026-10-14 with step 1, INET master `365c3941f7` in debug mode:

| `tcp.ini` | MATCH | DIVERGENCE | KERNEL_DRIFT | UNSUPPORTED |
| --- | --- | --- | --- | --- |
| the current file (explicit Linux parameters) | 288 | 15 | 12 | 3 |
| `LinuxTcp`, `mss`, `advertisedWindow` | 295 | 8 | 12 | 3 |
| `LinuxTcp`, `advertisedWindow` | 296 | 7 | 12 | 3 |
| `LinuxTcp`, `advertisedWindow`, INET `topic/tcp-packetdrill-repairs` | 302 | 1 | 12 | 3 |

`tcp.ini` does not need `mss`: master's default `mss = -1` gives 1460 bytes for IPv4 and 1440
bytes for IPv6, as Linux does for an MTU of 1500 bytes, and a SYN in LISTEN then takes TCP_MAXSEG
(INET D-99).

The 8 divergences with `LinuxTcp`, `mss` and `advertisedWindow` (7 scenarios; the PRR script is in
both sets). Each one also occurs with the current file, so none comes from `LinuxTcp`, and each one
is a defect of master:

| Script | First difference | Cause | Repair |
| --- | --- | --- | --- |
| `tcp/linux/tcp_fast_recovery_prr-ss-ack-below-snd_una-cubic`, `tcp/packetdrill/fast_recovery/prr-ss-ack-below-snd_una-cubic` | time, t=1.2435 | A | 1 |
| `tcp/linux/tcp_fastopen_server_client-ack-dropped-then-recovery-ms-timestamps` | time, t=2.01 | B | 2 |
| `tcp/linux/tcp_rcv_wnd_shrink_nomem` | packet, t=1 | C | 3 |
| `tcp/packetdrill/fast_retransmit/fr-4pkt` | time, t=1.5 | D | 4 |
| `tcp/packetdrill/fastopen/client/nonblocking-connect-bypass-errno` | time, t=9.735 | E | 5 |
| `tcp/packetdrill/fastopen/client/nonblocking-sendto-errnos` | time, t=4.0 | E | 5 |
| `tcp/packetdrill/mss/mss-setsockopt-tcp_maxseg-server` | packet, t=1.1 | F | 6, and step 3 |

- **A.** Master ignores the SACK blocks of an ACK below SND.UNA ("Old ACK"). RFC 6675 section 5
  updates the scoreboard on each ACK with SACK information (MUST), and Linux does too (the
  `old_ack` path of `tcp_ack()`). The script expects two segments on the late ACK with the newly
  SACKed 5001:7001. The TCP branch has the same gap. It passed because its PRR counted the SACKed
  bytes of a cumulative ACK again (INET D-28): it sent the two segments 2 ms early, inside the
  tolerance of packetdrill.
- **B.** A Fast Open server sends data in SYN_RCVD, and the ACK that completes the handshake
  carries SACK blocks. Master creates the SACK recovery at ESTABLISHED, so it drops the blocks ("no
  SACK-capable recovery in use"), and the TLP comes 1 s later in place of the fast retransmit. The
  TCP branch created the recovery at its first use; the landing of the split flavours lost that.
- **C.** With `windowAutoTuning`, master offers the auto-tuned window less the unread data. The
  right edge stays at 1000001, and master drops the 16th segment of 65000 bytes. Linux offers the
  free buffer at the scaling ratio, at most `rcv_ssthresh` (`__tcp_select_window()`), so the
  unread data reduce the offer only at that ratio.
- **D.** NewReno without SACK: `recover` starts at the ISS (RFC 6582 step 1), and step 2 asks for
  an ACK that covers more than `recover`. The ACK of the SYN covers only the ISS, so the loss of
  the first data segment gets no fast retransmit and waits for the RTO. Linux has no such check
  outside a recovery. FreeBSD keeps `snd_recover` as the next sequence number and starts it at the
  ISS, which is one above the ISS of RFC 6582. The TCP branch passed because its `recover` started
  at 0.
- **E.** The script sets TCP_SYNCNT after `sendto()` or `write()` sent the SYN.
  `TcpSocket::setSynRetries()` puts the value only in the open command (INET D-66), so the
  connection sends the SYN again until `synRetries` of `LinuxTcp` (6). Linux reads
  `icsk_syn_retries` at each timeout.
- **F.** TCP_MAXSEG on a listening socket lowers the send MSS, but the SYN-ACK announces the MSS
  that the open took from the `mss` parameter. Linux limits the MSS option of each connection of
  the listener by `user_mss`. With `mss = -1` the SYN in LISTEN takes TCP_MAXSEG, so step 3 alone
  repairs the script; the defect stays for an explicit `mss`.

## 5. The repairs in INET

One INET branch, `topic/tcp-packetdrill-repairs`, one commit with a module test for each:

| Repair | What | Cause |
| --- | --- | --- |
| 1 | process the SACK blocks of an ACK below SND.UNA, as RFC 6675 section 5 and Linux | A |
| 2 | create the SACK recovery when a Fast Open server sends data in SYN_RCVD | B |
| 3 | `windowAutoTuning` with a locked buffer: the unread data count once, in the free space of the buffer | C |
| 4 | NewReno: `recover` starts one below the ISS, so the first window has a fast retransmit | D |
| 5 | TCP_SYNCNT also after the open | E |
| 6 | TCP_MAXSEG on a listening socket also limits the MSS option | F |

The branch has these six commits, each with a module test that fails before it. With the branch,
the suite has 302 MATCH and 1 DIVERGENCE: the TCP branch had 303 MATCH.

The one divergence left is the last step of `tcp_rcv_wnd_shrink_nomem`. After repair 3 the
script gets as far as its last step, "We are allowed to go beyond the window and buffer with one
packet": Linux accepts a second 20000-byte segment into a locked buffer of 32000 bytes that holds
about 23000 bytes, and then offers a zero window. Master refuses the segment for two reasons: its
byte check refuses data beyond the first unread byte plus the buffer, and its truesize model
charges 33000 bytes for a 20000-byte segment (one page of order 3). A truesize as
`alloc_skb_with_frags()` gives (pages of the largest order that the rest fills), with memory
alone deciding for a locked buffer, repairs the script but breaks
`tcp_ooo-before-and-after-accept`, which needs the larger truesize. So neither model is the one
of Linux 7.1; the receive memory of INET needs a closer study of the Linux code (the tun
allocation, `tcp_try_coalesce()`, `tcp_can_ingest()`). The TCP branch passed the script only
because it grew a buffer that SO_RCVBUF had locked, which Linux does not do. This is an open item
for a later INET branch.

## 6. The record

The owner approved the INET repairs and this branch on 2026-10-14. The repairs landed on INET
master as `2424a1a865` (INET `plan/done/tcp-packetdrill-repairs.md`, decisions D-108 to D-113).

Against INET master `2424a1a865` in debug mode, with the `tcp.ini` of step 3, the suite has 302
MATCH, 12 KERNEL_DRIFT, 3 UNSUPPORTED_FEATURE and 1 DIVERGENCE, `tcp_rcv_wnd_shrink_nomem`
(section 5). The packetdrill wrappers of INET (`tests/protocol/tcp`, run with `INETGPL_ROOT` set to
this tree) give 333 tests: 328 PASS, 4 expected failures (3 scripts need a feature that INET does
not have; `Rfc9293ChecksumDefault`) and 1 unexpected failure, the same script. The suite also
confirms two values of `LinuxTcp` that INET S19b marked "verify": with the value of `Tcp`,
`abortOnDataAfterClose` fails 2 user_timeout scripts and `accEcnOptionEnabled` fails 28 AccECN
scripts. No script reaches `maxPersistTimeout`.

