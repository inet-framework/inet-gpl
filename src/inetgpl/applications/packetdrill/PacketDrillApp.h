//
// Copyright (C) 2014 Irene Ruengeler
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#ifndef __INETGPL_PACKETDRILLAPP_H
#define __INETGPL_PACKETDRILLAPP_H

#include <deque>
#include <set>

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/socket/SocketMap.h"
#include "inet/linklayer/tun/TunSocket.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/transportlayer/contract/sctp/SctpSocket.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/tcp/TcpConnection.h"
#include "inet/transportlayer/tcp_common/TcpHeader_m.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inetgpl/applications/packetdrill/PacketDrill.h"
#include "inetgpl/applications/packetdrill/PacketDrillUtils.h"

extern template class inet::OperationalMixin<omnetpp::cSimpleModule>;

namespace inetgpl {

class PacketDrill;
class PacketDrillScript;

/**
 * Implements the packetdrill application simple module. See the NED file for more info.
 */
class INETGPL_API PacketDrillApp : public ApplicationBase,
    public UdpSocket::ICallback, public TcpSocket::ICallback,
    public SctpSocket::ICallback, TunSocket::ICallback
{
  public:
    PacketDrillApp();
    virtual ~PacketDrillApp();

    int getLocalPort() const { return localPort; }
    int getRemotePort() const { return remotePort; }
    uint32_t getIdInbound() const { return idInbound; }
    uint32_t getIdOutbound() const { return idOutbound; }
    uint32_t getPeerTS() { return peerTS; }
    void increaseIdInbound() { idInbound++; }
    void increaseIdOutbound() { idOutbound++; }
    const L3Address getLocalAddress() { return localAddress; }
    const L3Address getRemoteAddress() { return remoteAddress; }
    uint32_t getPeerVTag() { return peerVTag; }
    uint32_t getLocalVTag() { return localVTag; }
    uint32_t getPeerCumTsn() { return peerCumTsn; }
    uint32_t getInitPeerTsn() { return initPeerTsn; }
    simtime_t getPeerHeartbeatTime() { return peerHeartbeatTime; }
    void setSeqNumMap(uint32_t ownNum, uint32_t liveNum) { seqNumMap[ownNum] = liveNum; }
    uint32_t getSeqNumMap(uint32_t ownNum) { return seqNumMap[ownNum]; }
    bool findSeqNumMap(uint32_t num);
    ChecksumMode getCrcMode() { return crcMode; }

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    void initialize(int stage) override;
    void handleMessageWhenUp(cMessage *msg) override;
    void finish() override;

    void handleTimer(cMessage *msg);

  private:
    PacketDrillScript *script = nullptr;
    PacketDrillConfig *config = nullptr;
    L3Address localAddress;
    L3Address remoteAddress;
    int localPort = 0;
    int remotePort = 0;
    int protocol = 0;
    int tcpConnId = -1;
    int sctpAssocId = -1;
    int tunSocketId = -1;
    int tunInterfaceId = -1;
    UdpSocket udpSocket;
    TcpSocket tcpSocket;
    SctpSocket sctpSocket;
    TunSocket tunSocket;
    SocketMap socketMap; // holds TCP connections with peers
    PacketDrill *pd = nullptr;
    bool msgArrived = false;
    bool recvFromSet = false;
    bool listenSet = false;
    bool acceptSet = false;
    bool establishedPending = false;
    bool abortSent = false;
    bool socketOptionsArrived_ = false;
    cPacketQueue *receivedPackets = nullptr;
    cPacketQueue *outboundPackets = nullptr;
    simtime_t simStartTime;
    simtime_t simRelTime;
    uint32_t expectedMessageSize = 0;
    // Sequence-number mapping between script and wire, following upstream
    // packetdrill's tcpdump convention (socket.h there): seq/ack numbers in
    // packets WITH the SYN flag are ABSOLUTE, all other packets' numbers are
    // RELATIVE to the first SYN of their direction.
    // relSequenceOut = the DUT's live ISN (captured from the live outbound
    // SYN); scriptIsnOut = the script's literal for that same SYN (usually 0,
    // but e.g. pure-syn-data writes "> S. 1234:1234"). relSequenceIn = the
    // peer's ISN, i.e. the injected SYN/SYN-ACK's literal (the tool "picks"
    // the remote live ISN, so wire == script literal there).
    uint32_t relSequenceOut = 0;
    uint32_t scriptIsnOut = 0;
    uint32_t relSequenceIn = 0;
    uint32_t peerTS = 0;
    uint16_t peerWindow = 0;
    uint16_t peerInStreams = 0;
    uint16_t peerOutStreams = 0;
    sctp::SctpCookie *peerCookie = nullptr;
    uint16_t peerCookieLength = 0;
    uint32_t initPeerTsn = 0;
    uint32_t initLocalTsn = 0;
    uint32_t localDiffTsn = 0;
    uint32_t peerCumTsn = 0;
    uint32_t localCumTsn = 0;
    uint32_t eventCounter = 0;
    uint32_t numEvents = 0;
    uint32_t idInbound = 0;
    uint32_t idOutbound = 0;
    uint32_t localVTag = 0;
    uint32_t peerVTag = 0;
    std::map<uint32_t, uint32_t> seqNumMap;
    simtime_t peerHeartbeatTime;
    cMessage *eventTimer = nullptr;
    // A %{ }% block requests tcp_info via an async STATUS command. When the block
    // sits at +0 after an inbound packet, that packet is still propagating
    // tun->ip->tcp (0-delay hops) while a direct STATUS command would reach TCP
    // first -- capturing a pre-ACK snapshot (e.g. cwnd one ACK stale). This timer
    // defers requestStatus() by an infinitesimal delay so it fires after the
    // same-instant inbound processing settles, matching packetdrill's synchronous
    // post-event tcp_info read.
    cMessage *statusRequestTimer = nullptr;
    ChecksumMode crcMode = CHECKSUM_MODE_UNDEFINED;
    int bytesSent = 0;

    // epoll: this framework only ever has one socket worth watching, so a
    // single registration (not a real per-fd table) covers the corpus.
    bool epollRegistered = false;
    uint32_t epollWatchedEvents = 0;
    bool epollInEdgePending = false;
    bool epollOutEdgePending = false;
    bool epollErrEdgePending = false; // set on each new error-queue arrival (zerocopy completion)
    bool epollOneshotFired = false; // EPOLLONESHOT: fd disarmed after one report until EPOLL_CTL_MOD

    // Socket-API extensions (harness upgrade for INET Workstreams F/G/H):
    // SO_ZEROCOPY gate for MSG_ZEROCOPY sends; SO_TIMESTAMPING's requested
    // SOF_ flag bits (INET models RX-only stamps -- TX bits are recorded so
    // recvmsg(MSG_ERRQUEUE) can report the honest gap); TCP_FASTOPEN_CONNECT
    // marker consumed by the next connect(); completed MSG_ZEROCOPY
    // notification ids collected from socketZerocopyCompletion() in send
    // order, drained by recvmsg(MSG_ERRQUEUE).
    bool zerocopyEnabled = false;
    int timestampingFlags = 0;
    bool fastopenConnectPending = false;
    std::deque<uint32_t> completedZerocopyIds;
    std::set<int> closedTcpConnIds; // close() already sent for these connection ids (duplicate close is a no-op)

    // GSO aggregation for outbound comparison: leg L runs the real kernel
    // with GSO, so corpus scripts assert super-segments (e.g. one 10000-byte
    // outbound packet) where INET emits wire-realistic MSS-sized segments.
    // When the script's expected outbound TCP payload exceeds the live
    // segment's, the expected packet parks here and consecutive
    // seq-contiguous live segments are accumulated against it until the
    // payload total matches (PSH compared leniently across the aggregate --
    // Linux only sets it on the final GSO sub-segment, and INET has no
    // push-on-queue-drain semantics at all; see the status report).
    inet::Packet *aggExpectedOutbound = nullptr;
    uint32_t aggRemainingPayload = 0;
    uint32_t aggNextSeq = 0;
    bool comparePshLeniently = false;

    // %{ }% Python-assertion blocks: each block's tcp_info-equivalent
    // snapshot (captured via an async TCP_C_STATUS request at the block's
    // scheduled time) plus its raw Python text are accumulated here, in
    // script order, and executed together as one python3 subprocess at the
    // very end of the script -- matching upstream packetdrill's actual
    // architecture (see plan doc), not per-block synchronous execution.
    std::string codeBlockBuffer;
    bool codeEventPending = false;
    const char *pendingCodeText = nullptr;

    // Set once every scripted event has been consumed (and every EXPECTED
    // outbound packet already matched). Real packetdrill ends the test at its
    // last script line; leg L (the golden) therefore never observes the DUT's
    // post-script timer activity (an RTO retransmit, a delayed ACK). INET's
    // simulation keeps running to the sim-time-limit, so those trailing packets
    // would otherwise be flagged as unexpected "wrong time" divergences. Once
    // this is set, socketDataArrived() ignores further outbound packets, giving
    // leg I the same observation window as leg L.
    bool scriptComplete = false;

  private:
    void scheduleEvent();

    void runEvent(PacketDrillEvent *event);
    void runSystemCallEvent(PacketDrillEvent *event, struct syscall_spec *syscall);
    void runCommandEvent(PacketDrillEvent *event); // timed backtick block: apply known-sysctl assignments
    void closeAllSockets();

    int syscallSocket(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallBind(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallListen(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallConnect(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallWrite(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallAccept(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallSetsockopt(struct syscall_spec *syscall, cQueue *args, char **error);

    int setsockoptTcpLevel(int level, cQueue *args, char **error);

    void sendTcpPayloadWithFlags(int64_t numBytes, int flags);

    int syscallGetsockopt(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallSendTo(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallRead(PacketDrillEvent *event, struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallRecvFrom(PacketDrillEvent *event, struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallClose(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallShutdown(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallSendMsg(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallRecvMsg(PacketDrillEvent *event, struct syscall_spec *syscall, cQueue *args, char **error);

    int verifyMsgErrQueue(struct msghdr_expr *msgExpr, struct syscall_spec *syscall, char **error);

    static int64_t tcpPayloadLength(inet::Packet *pkt);

    // TCP receive-stream model for read()/recv(): queued app-data messages
    // form one byte stream; reads may consume part of a message (Linux read
    // semantics), tracked by a byte offset into the front app-data message.
    int64_t availableAppBytes();
    void consumeAppBytes(int64_t count);
    omnetpp::cPacket *partialReadPkt = nullptr;
    int64_t partialReadOffset = 0;
    void startOutboundComparison(inet::Packet *expectedPacket, inet::Packet *livePacket);
    void continueOutboundAggregation(inet::Packet *livePacket);

    int verifyMsgControlInq(struct msghdr_expr *msgExpr, char **error);

    int syscallEpollCreate(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallEpollCtl(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallEpollWait(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallPoll(struct syscall_spec *syscall, cQueue *args, char **error);

    void runCodeEvent(PacketDrillEvent *event);

    std::string formatTcpInfoSnapshot(TcpStatusInfo *status);

    void executeCodeBlocks();

    int syscallSctpSendmsg(struct syscall_spec *syscall, cQueue *args, char **error);

    int syscallSctpSend(struct syscall_spec *syscall, cQueue *args, char **error);

    bool compareDatagram(Packet *storedDatagram, Packet *liveDatagram);

    bool compareUdpHeader(const Ptr<const UdpHeader>& storedUdp, const Ptr<const UdpHeader>& liveUdp);

    bool compareTcpHeader(const Ptr<const tcp::TcpHeader>& storedTcp, const Ptr<const tcp::TcpHeader>& liveTcp);

    bool compareSctpPacket(const Ptr<const sctp::SctpHeader>& storedSctp, const Ptr<const sctp::SctpHeader>& liveSctp);

    bool compareInitPacket(const sctp::SctpInitChunk *storedInitChunk, const sctp::SctpInitChunk *liveInitChunk);

    bool compareDataPacket(const sctp::SctpDataChunk *storedDataChunk, const sctp::SctpDataChunk *liveDataChunk);

    bool compareSackPacket(const sctp::SctpSackChunk *storedSackChunk, const sctp::SctpSackChunk *liveSackChunk);

    bool compareInitAckPacket(const sctp::SctpInitAckChunk *storedInitAckChunk, const sctp::SctpInitAckChunk *liveInitAckChunk);

    bool compareReconfigPacket(const sctp::SctpStreamResetChunk *storedReconfigChunk, const sctp::SctpStreamResetChunk *liveReconfigChunk);

    int verifyTime(enum eventTime_t timeType,
            simtime_t script_usecs, simtime_t script_usecs_end,
            simtime_t offset, simtime_t liveTime, const char *description);

    void adjustTimes(PacketDrillEvent *event);

    /** @name OperationalBase lifecycle methods */
    //@{
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;
    //@}

    /** @name TcpSocket::ICallback methods */
    //@{
    virtual void socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent) override;
    virtual void socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) override;
    virtual void socketEstablished(TcpSocket *socket) override;
    virtual void socketPeerClosed(TcpSocket *socket) override;
    virtual void socketClosed(TcpSocket *socket) override;
    virtual void socketFailure(TcpSocket *socket, int code) override;
    virtual void socketStatusArrived(TcpSocket *socket, TcpStatusInfo *status) override;
    virtual void socketZerocopyCompletion(TcpSocket *socket, unsigned int zerocopyId) override;
    virtual void socketDeleted(TcpSocket *socket) override {} // TODO
    //@}

    /** @name UdpSocket::ICallback methods */
    //@{
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
    virtual void socketClosed(UdpSocket *socket) override;
    //@}

    /** @name SctpSocket::ICallback methods */
    //@{
    virtual void socketDataArrived(SctpSocket *socket, Packet *packet, bool urgent) override;
    virtual void socketDataNotificationArrived(SctpSocket *socket, Message *msg) override;
    virtual void socketAvailable(SctpSocket *socket, Indication *indication) override;
    virtual void socketEstablished(SctpSocket *socket, unsigned long int buffer) override;
    virtual void socketOptionsArrived(SctpSocket *socket, Indication *indication) override;
    virtual void socketPeerClosed(SctpSocket *socket) override;
    virtual void socketClosed(SctpSocket *socket) override;
    virtual void socketFailure(SctpSocket *socket, int code) override;
    virtual void socketStatusArrived(SctpSocket *socket, SctpStatusReq *status) override;
    virtual void socketDeleted(SctpSocket *socket) override;
    virtual void sendRequestArrived(SctpSocket *socket) override;
    virtual void msgAbandonedArrived(SctpSocket *socket) override;
    virtual void shutdownReceivedArrived(SctpSocket *socket) override;
    virtual void sendqueueFullArrived(SctpSocket *socket) override;
    virtual void sendqueueAbatedArrived(SctpSocket *socket, unsigned long int buffer) override;
    virtual void addressAddedArrived(SctpSocket *socket, L3Address localAddr, L3Address remoteAddr) override;
    //@}

    /** @name TunSocket::ICallback methods */
    //@{
    virtual void socketDataArrived(TunSocket *socket, Packet *packet) override;
    virtual void socketClosed(TunSocket *socket) override;
    //@}
};

} // namespace inet

#endif

