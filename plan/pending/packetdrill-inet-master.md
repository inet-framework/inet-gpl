# Run the packetdrill suite against INET master, with LinuxTcp

Status: **in progress** — step 1 done in the tree, step 2 started.

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
| 1 | PacketDrillApp: SO_RCVBUF and TCP_SYNCNT as socket calls of INET | the five run-time writes go |
| 2 | (INET or here) one commit for each divergence that has a repair | see section 4 |
| 3 | tests/packetdrill: the host runs LinuxTcp | `tcp.ini` selects `LinuxTcp` and keeps `mss` and `advertisedWindow` |
| 4 | the record | the suite on master, the wrappers of INET |

## 4. The suite on master

Measured on 2026-10-14 with step 1, INET master `365c3941f7` in debug mode:

| `tcp.ini` | MATCH | DIVERGENCE | KERNEL_DRIFT | UNSUPPORTED |
| --- | --- | --- | --- | --- |
| the current file (explicit Linux parameters) | 288 | 15 | 12 | 3 |
| `LinuxTcp`, `mss`, `advertisedWindow` | 295 | 8 | 12 | 3 |

The 8 divergences with `LinuxTcp` (7 scenarios; the PRR script is in both sets):

| Script | First difference | Cause | Repair |
| --- | --- | --- | --- |
| `tcp/linux/tcp_fast_recovery_prr-ss-ack-below-snd_una-cubic`, `tcp/packetdrill/fast_recovery/prr-ss-ack-below-snd_una-cubic` | time, t=1.2435 | open | open |
| `tcp/linux/tcp_fastopen_server_client-ack-dropped-then-recovery-ms-timestamps` | time, t=2.01 | open | open |
| `tcp/linux/tcp_rcv_wnd_shrink_nomem` | packet, t=1 | open | open |
| `tcp/packetdrill/fast_retransmit/fr-4pkt` | time, t=1.5 | open | open |
| `tcp/packetdrill/fastopen/client/nonblocking-connect-bypass-errno` | time, t=9.735 | open | open |
| `tcp/packetdrill/fastopen/client/nonblocking-sendto-errnos` | time, t=4.0 | open | open |
| `tcp/packetdrill/mss/mss-setsockopt-tcp_maxseg-server` | packet, t=1.1 | open | open |

Each has one of three causes: a value of Linux that `LinuxTcp` lacks (repair in INET), a
deliberate difference of master from the TCP branch (a decision of the staged landing; then
`scripts.yaml` records it, as it records the kernel drift), or a defect of master (repair in
INET, with a module test).
