# TCP Oracle Scoreboard

Kernel: `7.1.1`  
INET commit: `45e49335b4f4`  
INETGPL commit: `08f79645af89`  
Scripts evaluated: 318

## Headline

| Verdict | Count | Share |
|---|---|---|
| DIVERGENCE | 256 | 81% |
| MATCH | 35 | 11% |
| ORACLE_SUSPECT | 27 | 8% |

## By category

This is the "state of INET TCP vs Linux" view: which parts of the protocol are MATCH-verified, which genuinely diverge, and which never even run (dialect gap / crash / unsupported config).

| Category | MATCH | DIVERGENCE | CRASH | DIALECT_GAP | UNSUPPORTED_FEATURE | ORACLE_SUSPECT | Total |
|---|---|---|---|---|---|---|---|
| fastopen | 1 | 70 | - | - | - | 10 | 81 |
| accecn | - | 58 | - | - | - | - | 58 |
| zerocopy | 6 | 15 | - | - | - | 1 | 22 |
| slow_start | - | 20 | - | - | - | - | 20 |
| blocking | 1 | 7 | - | - | - | - | 8 |
| eor | 6 | 2 | - | - | - | - | 8 |
| fast_recovery | - | 8 | - | - | - | - | 8 |
| sack | - | 8 | - | - | - | - | 8 |
| close | 6 | 1 | - | - | - | - | 7 |
| timestamping | - | 7 | - | - | - | - | 7 |
| cubic | - | 2 | - | - | - | 4 | 6 |
| nagle | - | 4 | - | - | - | 2 | 6 |
| shutdown | 3 | 2 | - | - | - | 1 | 6 |
| syscall_bad_arg | 2 | 4 | - | - | - | - | 6 |
| tcp_info | - | 6 | - | - | - | - | 6 |
| ts_recent | - | 5 | - | - | - | 1 | 6 |
| epoll | - | 1 | - | - | - | 3 | 4 |
| fast_retransmit | 1 | 3 | - | - | - | - | 4 |
| inq | - | 4 | - | - | - | - | 4 |
| limited_transmit | 2 | 2 | - | - | - | - | 4 |
| user_timeout | 2 | 2 | - | - | - | - | 4 |
| rcv | - | 3 | - | - | - | 1 | 4 |
| mss | 1 | 2 | - | - | - | - | 3 |
| notsent_lowat | - | 2 | - | - | - | 1 | 3 |
| cwnd_moderation | - | 1 | - | - | - | 1 | 2 |
| ecn | - | 2 | - | - | - | - | 2 |
| md5 | - | 2 | - | - | - | - | 2 |
| sendfile | 2 | - | - | - | - | - | 2 |
| splice | - | 2 | - | - | - | - | 2 |
| validate | - | 2 | - | - | - | - | 2 |
| basic | - | 2 | - | - | - | - | 2 |
| ooo | - | 2 | - | - | - | - | 2 |
| gro | - | - | - | - | - | 1 | 1 |
| ioctl | - | 1 | - | - | - | - | 1 |
| mtu_probe | - | - | - | - | - | 1 | 1 |
| disorder | 1 | - | - | - | - | - | 1 |
| dsack | - | 1 | - | - | - | - | 1 |
| rcv_zero_wnd | - | 1 | - | - | - | - | 1 |
| rfc5961 | 1 | - | - | - | - | - | 1 |
| rto | - | 1 | - | - | - | - | 1 |
| syncookies | - | 1 | - | - | - | - | 1 |

## Divergences (256)

### gtests:blocking/blocking-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.3s, event #34

### gtests:blocking/blocking-connect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #9

### gtests:blocking/blocking-write

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.6s, event #110
- unmapped knobs (possible attribution): --tolerance_usecs=10000

### gtests:cubic/cubic-rack-reo-timeout-retrans-failed-incoming-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cubic.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:cubic/cubic-rto-ss-ca-cwnd-bump

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cubic.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #51

### gtests:cwnd_moderation/cwnd-moderation-disorder-no-moderation

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #50

### gtests:ecn/ecn-uses-ect0

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #9

### gtests:eor/no-coalesce-retrans

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.217s, event #176

### gtests:epoll/epoll_in_edge

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected events -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #33

### gtests:fast_recovery/prr-ss-10pkt-lost-1

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #71

### gtests:fast_recovery/prr-ss-30pkt-lost-1_4-11_16

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #63

### gtests:fast_recovery/prr-ss-30pkt-lost1_4

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #71

### gtests:fast_recovery/prr-ss-ack-below-snd_una-cubic

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #71

### gtests:fast_retransmit/fr-4pkt-fack-last-byte

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #45

### gtests:fast_retransmit/fr-4pkt-fack-last-mss

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #45

### gtests:fast_retransmit/fr-4pkt-sack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #53

### gtests:fastopen/client/blocking-connect-bypass-errno

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:fastopen/client/blocking-connect-bypass

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:fastopen/client/blocking-sendmsg-multi-iov

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/blocking-sendto-errnos

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/blocking-sendto

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/cookie-less-sendto

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.05s, event #10

### gtests:fastopen/client/cookie-req-timeout

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/fastopen-connect-keepalive

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:fastopen/client/nonblocking-connect-bypass-errno

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12

### gtests:fastopen/client/nonblocking-connect-bypass

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12

### gtests:fastopen/client/nonblocking-sendmsg-multi-iov

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/nonblocking-sendto-empty-buf

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/client/nonblocking-sendto-errnos

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.015s, event #12

### gtests:fastopen/client/nonblocking-sendto-over-mss

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/client/poll

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/simultaneous-fast-open

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-icmp-unreach-frag-needed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-mss

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-only-syn-acked

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-partial-or-over-ack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-rtt-from-syn-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/syn-data-timeout

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:fastopen/client/synack-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10
- unmapped knobs (possible attribution): --tcp_ts_ecr_scaled

### gtests:fastopen/client/valid-cookie-format

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/basic-cookie-not-reqd

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16

### gtests:fastopen/server/basic-non-tfo-listener

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.7s, event #30

### gtests:fastopen/server/basic-rw

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/basic-zero-payload

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/fin-close-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/icmp-baseline

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/icmp-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/listener-closed-trigger-rst

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/opt34/basic-cookie-not-reqd

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16

### gtests:fastopen/server/opt34/basic-non-tfo-listener

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16

### gtests:fastopen/server/opt34/basic-rw

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/basic-zero-payload

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #26
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/fin-close-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/icmp-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/listener-closed-trigger-rst

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/pure-syn-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1

### gtests:fastopen/server/opt34/reset-after-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/reset-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #16
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/reset-close-with-unread-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/reset-non-tfo-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/opt34/unread-data-closed-trigger-rst

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --remote_ip=192.0.2.1, --local_ip=192.168.0.1

### gtests:fastopen/server/pure-syn-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### gtests:fastopen/server/reset-after-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/reset-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/reset-close-with-unread-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/reset-non-tfo-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:fastopen/server/unread-data-closed-trigger-rst

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### gtests:inq/client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12

### gtests:inq/server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Wrong payload length -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.01s, event #29

### gtests:ioctl/ioctl-siocinq-fin

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.4s, event #32

### gtests:limited_transmit/limited-transmit-sack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #63

### gtests:md5/md5-only-on-client-ack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_ipv4.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.04s, event #34

### gtests:mss/mss-setsockopt-tcp_maxseg-client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #11

### gtests:mss/mss-setsockopt-tcp_maxseg-server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #17

### gtests:nagle/sendmsg_msg_more

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Timing error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.22s, event #28

### gtests:nagle/sockopt_cork_nodelay

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.08s, event #41

### gtests:notsent_lowat/notsent-lowat-setsockopt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.23s, event #77

### gtests:notsent_lowat/notsent-lowat-sysctl

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.23s, event #75

### gtests:sack/sack-route-refresh-ip-tos

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:sack/sack-shift-sacked-2-6-8-3-9-nofack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #71

### gtests:sack/sack-shift-sacked-7-3-4-8-9-fack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #63

### gtests:sack/sack-shift-sacked-7-5-6-8-9-fack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #63

### gtests:shutdown/shutdown-rd-wr-close

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.21s, event #34

### gtests:shutdown/shutdown-rdwr-send-queue-ack-close

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.213s, event #71

### gtests:slow_start/slow-start-ack-per-1pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.64s, event #175

### gtests:slow_start/slow-start-ack-per-2pkt-send-5pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:slow_start/slow-start-ack-per-2pkt-send-6pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:slow_start/slow-start-ack-per-2pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.62s, event #76

### gtests:slow_start/slow-start-ack-per-4pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.64s, event #82

### gtests:slow_start/slow-start-after-idle

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.3s, event #111

### gtests:slow_start/slow-start-after-win-update

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.3s, event #113

### gtests:slow_start/slow-start-app-limited-9-packets-out

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:slow_start/slow-start-app-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:slow_start/slow-start-fq-ack-per-2pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### gtests:splice/tcp_splice_loop_test

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #34

### gtests:syscall_bad_arg/fastopen-invalid-buf-ptr

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:syscall_bad_arg/syscall-invalid-buf-ptr

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.4s, event #37

### gtests:tcp_info/tcp-info-last_data_recv

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:tcp_info/tcp-info-rwnd-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:tcp_info/tcp-info-sndbuf-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:timestamping/client-only-last-byte

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:timestamping/partial

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### gtests:timestamping/server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: TX timestamping (SCM_TIMESTAMPING) not modeled in INET -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.03s, event #53

### gtests:ts_recent/fin_tsval

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000, --tolerance_usecs=7000

### gtests:ts_recent/reset_tsval

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### gtests:user_timeout/user-timeout-probe

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_timer.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.5s, event #44

### gtests:validate/validate-established-no-flags

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.23s, event #36

### gtests:zerocopy/client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### gtests:zerocopy/closed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #12

### gtests:zerocopy/epoll_edge

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected event count -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #65

### gtests:zerocopy/epoll_exclusive

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected event count -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #65

### gtests:zerocopy/epoll_oneshot

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected events -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #64

### gtests:zerocopy/fastopen-client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12

### gtests:zerocopy/fastopen-server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #17

### kernel:tcp_accecn_2nd_data_as_first

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.052s, event #15

### kernel:tcp_accecn_2nd_data_as_first_connect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_3rd_ack_after_synack_rxmt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_3rd_ack_ce_updates_received_ce

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.052s, event #15

### kernel:tcp_accecn_3rd_ack_lost_data_ce

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.052s, event #15

### kernel:tcp_accecn_3rd_dups

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_acc_ecn_disabled

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_accecn_then_notecn_syn

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_accecn_to_rfc3168

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.066s, event #27

### kernel:tcp_accecn_client_accecn_options_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15
- unmapped knobs (possible attribution): net.ipv4.tcp_ecn_option_beacon=1

### kernel:tcp_accecn_client_accecn_options_lost

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_clientside_disabled

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_close_local_close_then_remote_fin

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.01s, event #18

### kernel:tcp_accecn_delivered_2ndlargeack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.076s, event #57

### kernel:tcp_accecn_delivered_falseoverflow_detect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_delivered_largeack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.076s, event #57

### kernel:tcp_accecn_delivered_largeack2

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.076s, event #57

### kernel:tcp_accecn_delivered_maxack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.076s, event #57

### kernel:tcp_accecn_delivered_updates

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_ecn3

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_ecn_field_updates_opt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_ipflags_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9
- unmapped knobs (possible attribution): --tolerance_usecs=50000

### kernel:tcp_accecn_listen_opt_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_multiple_syn_ack_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_multiple_syn_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_negotiation_bleach

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_negotiation_connect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_negotiation_listen

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_negotiation_noopt_connect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_negotiation_optenable

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_no_ecn_after_accecn

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_noopt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.076s, event #30

### kernel:tcp_accecn_noprogress

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_notecn_then_accecn_syn

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.104s, event #23

### kernel:tcp_accecn_rfc3168_to_fallback

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.066s, event #27

### kernel:tcp_accecn_rfc3168_to_rfc3168

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.066s, event #27

### kernel:tcp_accecn_sack_space_grab

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### kernel:tcp_accecn_sack_space_grab_with_ts

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### kernel:tcp_accecn_serverside_accecn_disabled1

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_serverside_accecn_disabled2

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_serverside_broken

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_serverside_ecn_disabled

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_serverside_only

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_syn_ace_flags_acked_after_retransmit

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_syn_ace_flags_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_syn_ack_ace_flags_acked_after_retransmit

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_syn_ack_ace_flags_drop

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_syn_ce

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_syn_ect0

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_syn_ect1

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_synack_ce

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_synack_ce_updates_delivered_ce

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.052s, event #15
- unmapped knobs (possible attribution): net.ipv4.tcp_ecn_fallback=0

### kernel:tcp_accecn_synack_ect0

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_synack_ect1

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_synack_rexmit

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.004s, event #9

### kernel:tcp_accecn_synack_rxmt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15

### kernel:tcp_accecn_tsnoprogress

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000, --tolerance_usecs=7000

### kernel:tcp_accecn_tsprogress

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### kernel:tcp_basic_client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #9

### kernel:tcp_basic_server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #34

### kernel:tcp_blocking_blocking-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.3s, event #34

### kernel:tcp_blocking_blocking-connect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #9

### kernel:tcp_blocking_blocking-read

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15
- unmapped knobs (possible attribution): --tolerance_usecs=10000

### kernel:tcp_blocking_blocking-write

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.6s, event #110
- unmapped knobs (possible attribution): --tolerance_usecs=10000

### kernel:tcp_close_no_rst

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### kernel:tcp_dsack_mult

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### kernel:tcp_ecn_ecn-uses-ect0

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.002s, event #9

### kernel:tcp_eor_no-coalesce-retrans

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.217s, event #176

### kernel:tcp_fast_recovery_prr-ss-10pkt-lost-1

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #71

### kernel:tcp_fast_recovery_prr-ss-30pkt-lost-1_4-11_16

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #63

### kernel:tcp_fast_recovery_prr-ss-30pkt-lost1_4

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #71

### kernel:tcp_fast_recovery_prr-ss-ack-below-snd_una-cubic

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.01s, event #71

### kernel:tcp_fastopen_server_basic-cookie-not-reqd

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #16

### kernel:tcp_fastopen_server_basic-no-setsockopt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_basic-non-tfo-listener

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_basic-pure-syn-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #16

### kernel:tcp_fastopen_server_basic-rw

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_basic-zero-payload

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_client-ack-dropped-then-recovery-ms-timestamps

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### kernel:tcp_fastopen_server_experimental_option

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_fin-close-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_icmp-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2
- unmapped knobs (possible attribution): --ip_version=ipv4

### kernel:tcp_fastopen_server_reset-after-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_reset-before-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_reset-close-with-unread-data

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_reset-non-tfo-socket

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_sockopt-fastopen-key

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_trigger-rst-listener-closed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_trigger-rst-reconnect

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_fastopen_server_trigger-rst-unread-data-closed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_fastopen.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_inq_client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12

### kernel:tcp_inq_server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### kernel:tcp_limited_transmit_limited-transmit-sack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #63

### kernel:tcp_md5_md5-only-on-client-ack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_ipv4.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.04s, event #34

### kernel:tcp_nagle_sendmsg_msg_more

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: Timing error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.22s, event #28

### kernel:tcp_nagle_sockopt_cork_nodelay

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_output.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.08s, event #41

### kernel:tcp_ooo-before-and-after-accept

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### kernel:tcp_ooo_rcv_mss

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15

### kernel:tcp_rcv_big_endseq

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #16

### kernel:tcp_rcv_neg_window

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #16

### kernel:tcp_rcv_wnd_shrink_allowed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): net.ipv4.tcp_shrink_window=1

### kernel:tcp_rcv_zero_wnd_fin

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #16

### kernel:tcp_rto_synack_rto_max

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_timer.c`
- message: Script error -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #2

### kernel:tcp_sack_sack-route-refresh-ip-tos

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10

### kernel:tcp_sack_sack-shift-sacked-2-6-8-3-9-nofack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #71

### kernel:tcp_sack_sack-shift-sacked-7-3-4-8-9-fack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #63

### kernel:tcp_sack_sack-shift-sacked-7-5-6-8-9-fack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_recovery.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.1s, event #63

### kernel:tcp_slow_start_slow-start-ack-per-1pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.64s, event #175

### kernel:tcp_slow_start_slow-start-ack-per-2pkt-send-5pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### kernel:tcp_slow_start_slow-start-ack-per-2pkt-send-6pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### kernel:tcp_slow_start_slow-start-ack-per-2pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.62s, event #76

### kernel:tcp_slow_start_slow-start-ack-per-4pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.64s, event #82

### kernel:tcp_slow_start_slow-start-after-idle

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.3s, event #111

### kernel:tcp_slow_start_slow-start-after-win-update

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: outbound segment does not continue the expected GSO super-segment -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.3s, event #113

### kernel:tcp_slow_start_slow-start-app-limited-9-packets-out

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### kernel:tcp_slow_start_slow-start-app-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### kernel:tcp_slow_start_slow-start-fq-ack-per-2pkt

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_cong.c, ~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: %{ }% assertion failed: Traceback (most recent call last):

### kernel:tcp_splice_tcp_splice_loop_test

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #34

### kernel:tcp_syncookies_ip4_9k

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/syncookies.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --ip_version=ipv4

### kernel:tcp_syscall_bad_arg_fastopen-invalid-buf-ptr

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_syscall_bad_arg_syscall-invalid-buf-ptr

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.4s, event #37

### kernel:tcp_tcp_info_tcp-info-last_data_recv

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_tcp_info_tcp-info-rwnd-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_tcp_info_tcp-info-sndbuf-limited

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_timestamping_client-only-last-byte

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_timestamping_partial

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11

### kernel:tcp_timestamping_server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: TX timestamping (SCM_TIMESTAMPING) not modeled in INET -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.03s, event #53

### kernel:tcp_timestamping_tcp_tx_timestamp_bug

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #11
- unmapped knobs (possible attribution): net.ipv4.tcp_min_tso_segs=70, --tolerance_usecs=1000000

### kernel:tcp_ts_recent_fin_tsval

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000, --tolerance_usecs=7000

### kernel:tcp_ts_recent_invalid_ack

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #15

### kernel:tcp_ts_recent_reset_tsval

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #15
- unmapped knobs (possible attribution): --tcp_ts_tick_usecs=1000

### kernel:tcp_user_timeout_user-timeout-probe

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_timer.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.5s, event #44

### kernel:tcp_validate_validate-established-no-flags

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp_input.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.23s, event #36

### kernel:tcp_zerocopy_client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #10
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_closed

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.1s, event #12
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_epoll_edge

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected event count -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #65
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_epoll_exclusive

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected event count -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #65
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_epoll_oneshot

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: epoll_wait returned unexpected events -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #64
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_fastopen-client

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1s, event #12
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_fastopen-server

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Datagrams are not the same -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=1.2s, event #17
- unmapped knobs (possible attribution): --send_omit_free

### kernel:tcp_zerocopy_maxfrags

- kernel source hint: `~/w/kernel/linux-7.2-rc2/net/ipv4/tcp.c`
- message: Packet arrived at the wrong time -- in module (inetgpl::PacketDrillApp) OracleTcpHost.pdhost.tunApp[0] (id=16), at t=2.2s, event #49
- unmapped knobs (possible attribution): --send_omit_free

## Oracle-suspect (27, excluded from MATCH/DIVERGENCE)

Leg L (the real kernel) itself did not pass, erred, or has no golden result -- these scripts are not a trustworthy contract on this kernel and are not counted toward INET's pass/fail.

- **gtests:cubic/cubic-bulk-166k-idle-restart**: leg_l=L_ERROR
- **gtests:cubic/cubic-bulk-166k**: leg_l=L_ERROR
- **gtests:cubic/cubic-hystart-delay-min-rtt-jumps-downward**: leg_l=L_ERROR
- **gtests:cubic/cubic-hystart-delay-rtt-jumps-upward**: leg_l=L_ERROR
- **gtests:cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700**: leg_l=L_ERROR
- **gtests:epoll/epoll_out_edge**: leg_l=L_FAIL
- **gtests:epoll/epoll_out_edge_default_notsent_lowat**: leg_l=L_FAIL
- **gtests:epoll/epoll_out_edge_notsent_lowat**: leg_l=L_FAIL
- **gtests:fastopen/client/fallback-exp-opt**: leg_l=L_ERROR
- **gtests:fastopen/client/nonblocking-sendto**: leg_l=L_ERROR
- **gtests:fastopen/server/client-ack-dropped-then-recovery-ms-timestamps**: leg_l=L_FAIL
- **gtests:fastopen/server/opt34/simple1**: leg_l=L_FAIL
- **gtests:fastopen/server/opt34/simple2**: leg_l=L_FAIL
- **gtests:fastopen/server/opt34/simple3**: leg_l=L_FAIL
- **gtests:fastopen/server/simple1**: leg_l=L_FAIL
- **gtests:fastopen/server/simple2**: leg_l=L_FAIL
- **gtests:fastopen/server/simple3**: leg_l=L_FAIL
- **gtests:fastopen/server/sockopt-fastopen-key**: leg_l=L_FAIL
- **gtests:gro/gro-mss-option**: leg_l=L_FAIL
- **gtests:mtu_probe/basic-v4**: leg_l=L_ERROR
- **gtests:nagle/https_client**: leg_l=L_FAIL
- **gtests:notsent_lowat/notsent-lowat-default**: leg_l=L_FAIL
- **gtests:shutdown/shutdown-rdwr-write-queue-close**: leg_l=L_FAIL
- **gtests:ts_recent/invalid_ack**: leg_l=L_FAIL
- **gtests:zerocopy/maxfrags**: leg_l=L_FAIL
- **kernel:tcp_nagle_https_client**: leg_l=L_FAIL
- **kernel:tcp_rcv_wnd_shrink_nomem**: leg_l=L_ERROR

