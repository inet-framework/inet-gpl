//
// Copyright (C) 2015 Irene Ruengeler
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#include "inetgpl/applications/packetdrill/PacketDrillApp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <climits>
#include <cmath>
#include <map>
#include <regex>
#include <sstream>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <netinet/tcp.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h> // SOF_TIMESTAMPING_TX_* flags for TX timestamping

#include "inetgpl/applications/packetdrill/PacketDrillInfo_m.h"
#include "inetgpl/applications/packetdrill/PacketDrillUtils.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/chunk/ByteCountChunk.h"
#include "inet/common/TimeTag_m.h"
#include "inet/common/lifecycle/ModuleOperations.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/socket/SocketTag_m.h"
#include "inet/common/stlutils.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/configurator/ipv4/Ipv4NodeConfigurator.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/IcmpHeader_m.h"
#include "inet/transportlayer/contract/sctp/SctpCommand_m.h"
#include "inet/transportlayer/tcp/Tcp.h"
#include "inet/transportlayer/contract/tcp/TcpSendEorTag_m.h"
#include "inet/transportlayer/contract/tcp/TcpSendMoreTag_m.h"
#include "inet/transportlayer/contract/tcp/TcpZerocopyTag_m.h"
#include "inet/transportlayer/sctp/SctpAssociation.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace inetgpl {

Define_Module(PacketDrillApp);

using namespace sctp;
using namespace tcp;

#define MSGKIND_START    0
#define MSGKIND_EVENT    1
#define MSGKIND_STATUS_REQUEST 2
#define MSGKIND_POLL_DEFERRED  3
#define MSGKIND_WRITER_UNBLOCK 4

PacketDrillApp::PacketDrillApp()
{
}

void PacketDrillApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // parameters
        msgArrived = false;
        recvFromSet = false;
        listenSet = false;
        acceptSet = false;
        establishedPending = false;
        socketOptionsArrived_ = false;
        abortSent = false;
        receivedPackets = new cPacketQueue("receiveQueue");
        outboundPackets = new cPacketQueue("outboundPackets");
        expectedMessageSize = 0;
        eventCounter = 0;
        numEvents = 0;
        localVTag = 0;
        eventTimer = new cMessage("event timer", MSGKIND_EVENT);
        // Real packetdrill's tuntap write is synchronous: the kernel fully
        // processes an injected packet before the next script line runs. In
        // the simulation an injected packet traverses the stack in several
        // same-simtime events, so run each script event AFTER all same-time
        // default-priority events (in-flight packets) have settled -- else a
        // "+0" syscall right after an inbound injection (e.g. epoll_wait
        // asserting a zerocopy completion the in-flight ACK delivers) sees
        // pre-packet state that the real kernel never exposes.
        eventTimer->setSchedulingPriority(100);
        statusRequestTimer = new cMessage("status request", MSGKIND_STATUS_REQUEST);
        pollTimer = new cMessage("deferred poll", MSGKIND_POLL_DEFERRED);
        writerUnblockTimer = new cMessage("writer unblock", MSGKIND_WRITER_UNBLOCK);
        simStartTime = simTime();
        simRelTime = simTime();
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        if (operationalState != OPERATING)
            throw cRuntimeError("This module doesn't support starting in NOT_OPERATING state");
        pd = new PacketDrill(this);
        config = new PacketDrillConfig();
        script = new PacketDrillScript(par("scriptFile").stringValue());
        localAddress = L3Address(par("localAddress"));
        remoteAddress = L3Address(par("remoteAddress"));
        localPort = par("localPort");
        remotePort = par("remotePort");
        explicitRead = par("explicitRead");
        const char *crcModeString = par("crcMode");
        crcMode = parseChecksumMode(crcModeString, false);
        const char *interface = par("interface");
//        const char *interfaceTableModule = par("interfaceTableModule");
        IInterfaceTable *interfaceTable = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        NetworkInterface *networkInterface = interfaceTable->findInterfaceByName(interface);
        if (networkInterface == nullptr)
            throw cRuntimeError("TUN interface not found: %s", interface);
        auto idat = networkInterface->getProtocolDataForUpdate<Ipv4InterfaceData>();
        idat->setIPAddress(localAddress.toIpv4());
        tunSocket.setOutputGate(gate("socketOut"));
        tunSocket.setCallback(this);
        tunSocket.open(networkInterface->getInterfaceId());
        tunInterfaceId = networkInterface->getInterfaceId();
        tunSocketId = tunSocket.getSocketId();

        cMessage *timeMsg = new cMessage("PacketDrillAppTimer", MSGKIND_START);
        scheduleAt(par("startTime"), timeMsg);
    }
}

void PacketDrillApp::socketDataArrived(UdpSocket *socket, Packet *packet)
{
    if (recvFromSet) {
        recvFromSet = false;
        msgArrived = false;
        if (!(packet->getByteLength() == expectedMessageSize)) {
            throw cTerminationException("Packetdrill error: Received data has unexpected size");
        }
        if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
            eventCounter++;
            scheduleEvent();
        }
        delete packet;
    }
    else {
        PacketDrillInfo *info = new PacketDrillInfo();
        info->setLiveTime(getSimulation()->getSimTime());
        packet->setContextPointer(info);
        receivedPackets->insert(packet);
        msgArrived = true;
        if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
            eventCounter++;
            scheduleEvent();
        }
    }
}

// UdpSocket:

void PacketDrillApp::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
}

void PacketDrillApp::socketClosed(UdpSocket *socket)
{
}

// TcpSocket:

void PacketDrillApp::socketDataArrived(TcpSocket *socket, Packet *msg, bool urgent)
{
    // Mirrors the working UDP socketDataArrived() below: the socket runs in
    // TcpSocket's default autoRead mode, so data is pushed up as it arrives
    // rather than pulled via an explicit TCP_C_READ command (a command this
    // handler used to send anyway, as a plain TcpCommand rather than a
    // TcpReadCommand -- unreachable in practice since it only fired when
    // data had already arrived, but would have crashed process_READ_REQUEST()
    // if it ever had). The previous version also discarded the payload
    // (`delete msg`) without ever queuing it, so read()/recvfrom()/recvmsg()
    // could never actually verify TCP payload lengths.
    epollInEdgePending = true;
    PacketDrillInfo *info = new PacketDrillInfo();
    info->setLiveTime(getSimulation()->getSimTime());
    msg->setContextPointer(info);
    receivedPackets->insert(msg);
    msgArrived = true;
    checkDeferredPollNow();
    if (recvFromSet) {
        // a read()/recv() is blocked on this stream: complete it once enough
        // bytes have accumulated (stream semantics -- the read may span
        // several arrival chunks), else keep waiting
        if (availableAppBytes() < expectedMessageSize)
            return;
        recvFromSet = false;
        consumeAppBytes(expectedMessageSize);
    }
    if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
        eventCounter++;
        scheduleEvent();
    }
}

void PacketDrillApp::socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo)
{
    // Explicit-read mode defers the TCP-level accept until the SCRIPT's
    // accept() runs: Linux keeps a not-yet-accepted socket embryonic (its
    // rcvbuf never grows under OOO pressure -- tcp_data_queue_ofo's "do not
    // grow rcvbuf for not-yet-accepted or orphaned sockets" gate;
    // ooo-before-and-after-accept pins both halves), and with autoRead off
    // no data indications are needed before the accept anyway.
    if (explicitRead && !acceptSet) {
        pendingAvailableInfo = *availableInfo;
        pendingAvailableSocket = socket;
        availablePending = true;
        return;
    }
    completeTcpAccept(socket, availableInfo);
}

void PacketDrillApp::completeTcpAccept(TcpSocket *socket, TcpAvailableInfo *availableInfo)
{
    // new TCP connection -- create new socket object and server process
    TcpSocket *newSocket = new TcpSocket(availableInfo);
    newSocket->setOutputGate(gate("socketOut"));
    newSocket->setCallback(this);
    socketMap.addSocket(newSocket);
    // the accepted socket carries the server's byte stream: explicit-read
    // READ requests must go to it, not to the primary/listener socket
    lastDataSocketId = newSocket->getSocketId();
    socket->accept(newSocket->getSocketId());
}

void PacketDrillApp::socketEstablished(TcpSocket *socket)
{
}

void PacketDrillApp::socketPeerClosed(TcpSocket *socket)
{
    peerFinPending = true;
    peerClosedSeen = true; // POLLRDHUP: half-close is a persistent condition
}

void PacketDrillApp::socketClosed(TcpSocket *socket)
{
    delete socketMap.removeSocket(socket);
}

void PacketDrillApp::socketFailure(TcpSocket *socket, int code)
{
    delete socketMap.removeSocket(socket);
}

// SctpSocket:

void PacketDrillApp::socketDataArrived(SctpSocket *socket, Packet *packet, bool urgent)
{
    PacketDrillEvent *event = check_and_cast<PacketDrillEvent *>(script->getEventList()->get(eventCounter));
    if (verifyTime(event->getTimeType(), event->getEventTime(), event->getEventTimeEnd(),
            event->getEventOffset(), getSimulation()->getSimTime(), "inbound packet") == STATUS_ERR)
    {
        delete packet;
        throw cTerminationException("Packetdrill error: Packet arrived at the wrong time");
    }
    if (!(packet->getByteLength() == expectedMessageSize)) {
        throw cTerminationException("Packetdrill error: Delivered message has wrong size");
    }
    msgArrived = false;
    recvFromSet = false;
    if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
        eventCounter++;
        scheduleEvent();
    }
}

void PacketDrillApp::socketDataNotificationArrived(SctpSocket *socket, Message *msg)
{
    if (recvFromSet) {
        Packet *cmsg = new Packet("ReceiveRequest", SCTP_C_RECEIVE);
        auto cmd = cmsg->addTag<SctpSendReq>();
        cmd->setSocketId(sctpAssocId);
        cmsg->addTag<SocketReq>()->setSocketId(sctpAssocId);
        cmsg->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::sctp);
        cmd->setSid(0);
        send(cmsg, "socketOut"); // send to SCTP
        recvFromSet = false;
    }
    if (sctpSocket.getState() == SctpSocket::CLOSED) {
        sctpSocket.abort();
        abortSent = true;
    }
    if (!abortSent)
        msgArrived = true;
}

void PacketDrillApp::socketAvailable(SctpSocket *socket, Indication *indication)
{
    SctpSocket *newSocket = new SctpSocket(indication);
    newSocket->setOutputGate(gate("socketOut"));
    newSocket->setCallback(this);
    socketMap.addSocket(newSocket);
    int newSocketId = newSocket->getSocketId();
    sctpAssocId = newSocketId;
    EV_INFO << "Sending accept socket id request ..." << endl;
    socket->acceptSocket(newSocketId);
    delete indication;
}

void PacketDrillApp::socketEstablished(SctpSocket *socket, unsigned long int buffer)
{
    EV_INFO << "SCTP_I_ESTABLISHED" << endl;
}

void PacketDrillApp::socketOptionsArrived(SctpSocket *socket, Indication *indication)
{
    sctpSocket.setUserOptions((SocketOptions *)(indication->getContextPointer()));
    socketOptionsArrived_ = true;
    if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
        eventCounter++;
        scheduleEvent();
    }
    delete indication;
}

void PacketDrillApp::socketPeerClosed(SctpSocket *socket) {}

void PacketDrillApp::socketClosed(SctpSocket *socket)
{
    delete socketMap.removeSocket(socket);
}

void PacketDrillApp::socketFailure(SctpSocket *socket, int code)
{
    delete socketMap.removeSocket(socket);
}

void PacketDrillApp::socketStatusArrived(SctpSocket *socket, SctpStatusReq *status) {}
void PacketDrillApp::socketDeleted(SctpSocket *socket) {}
void PacketDrillApp::sendRequestArrived(SctpSocket *socket) {}
void PacketDrillApp::msgAbandonedArrived(SctpSocket *socket) {}
void PacketDrillApp::shutdownReceivedArrived(SctpSocket *socket) {}
void PacketDrillApp::sendqueueFullArrived(SctpSocket *socket) {}
void PacketDrillApp::sendqueueAbatedArrived(SctpSocket *socket, unsigned long int buffer) {}
void PacketDrillApp::addressAddedArrived(SctpSocket *socket, L3Address localAddr, L3Address remoteAddr) {}

void PacketDrillApp::socketDataArrived(TunSocket *socket, Packet *packet)
{
    // received from tunnel interface
    if (scriptComplete) {
        // Every scripted event has already been consumed and every expected
        // outbound packet matched; real packetdrill would have ended the test
        // here. Ignore INET's post-script timer traffic (RTO retransmit,
        // delayed ACK) so the INET run observes the same window as the Linux run.
        delete (PacketDrillInfo *)packet->getContextPointer();
        delete packet;
        return;
    }
    // TX timestamping: this is the single choke point for every real INET outbound
    // segment (before GSO aggregation), so SCM_TSTAMP_SCHED/SND for a key byte are
    // taken from the segment that actually carries it -- even when it lands in a
    // later, cwnd-released segment rather than the one produced at write time.
    recordTxTimestampSend(packet);
    // Track the DUT's latest outbound TS value so an injected inbound segment can
    // echo it as TSecr (peerTS). Without this peerTS stayed 0, every injected ACK
    // echoed ecr=0, and the DUT's TS-based RTT measurement mapped to send-time 0 --
    // blowing SRTT up to the absolute sim time on any TS-enabled connection.
    {
        auto ipH = packet->peekAtFront<Ipv4Header>();
        if (ipH->getProtocolId() == IP_PROT_TCP) {
            auto tcpH = packet->peekDataAt<TcpHeader>(ipH->getChunkLength());
            for (unsigned int i = 0; i < tcpH->getHeaderOptionArraySize(); i++) {
                if (auto *tsOpt = dynamic_cast<const TcpOptionTimestamp *>(tcpH->getHeaderOption(i))) {
                    peerTS = tsOpt->getSenderTimestamp();
                    break;
                }
            }
        }
    }
    // TCPI_OPT_SYN_DATA wire shadow (see the header): record the DUT's
    // data-bearing SYN, and detect its data being acked by an outbound
    // SYN-ACK's ackNo when the DUT is the server.
    {
        auto ipH = packet->peekAtFront<Ipv4Header>();
        if (ipH->getProtocolId() == IP_PROT_TCP) {
            auto tcpH = packet->peekDataAt<TcpHeader>(ipH->getChunkLength());
            int64_t payload = (B(ipH->getTotalLengthField()) - ipH->getChunkLength() - tcpH->getHeaderLength()).get<B>();
            if (tcpH->getSynBit() && !tcpH->getAckBit() && payload > 0)
                tfoShadowSynDataEndOut = tcpH->getSequenceNo() + 1 + payload;
            if (tcpH->getSynBit() && tcpH->getAckBit() && tfoShadowSynDataEndIn != 0
                    && !seqLess(tcpH->getAckNo(), tfoShadowSynDataEndIn))
                tfoSynDataAckedShadow = true;
        }
    }
    // Real packetdrill filters captured packets by the socket-under-test's
    // 4-tuple (its packet-socket filter): a trailing FIN/RST/rexmit from an
    // ALREADY-CLOSED earlier connection of a multi-connection script is
    // invisible to it. Without this filter such a straggler (srcPort = the
    // previous conn's port) gets compared against the NEXT connection's
    // expectation and fails on "srcPort expected N+1 actual N".
    {
        auto ipH = packet->peekAtFront<Ipv4Header>();
        if (ipH->getProtocolId() == IP_PROT_TCP) {
            auto tcpH = packet->peekDataAt<TcpHeader>(ipH->getChunkLength());
            if (tcpH->getSrcPort() != localPort || tcpH->getDestPort() != remotePort) {
                EV_DETAIL << "Ignoring outbound packet from defunct connection (srcPort="
                          << tcpH->getSrcPort() << ", current localPort=" << localPort << ")\n";
                delete (PacketDrillInfo *)packet->getContextPointer();
                delete packet;
                return;
            }
        }
    }
    if (aggExpectedOutbound != nullptr) {
        // an expected GSO super-segment is being matched by consecutive live
        // MSS-sized segments -- this packet continues (or completes) it
        continueOutboundAggregation(packet);
        return;
    }
    if (outboundPackets->getLength() == 0) {
        cEvent *nextMsg = getSimulation()->getScheduler()->guessNextEvent();
        if (nextMsg) {
            if ((simTime() + par("latency")) < nextMsg->getArrivalTime()) {
                delete (PacketDrillInfo *)packet->getContextPointer();
                delete packet;
                throw cTerminationException("Packetdrill error: Packet arrived at the wrong time");
            }
            else {
                PacketDrillInfo *info = new PacketDrillInfo();
                info->setLiveTime(getSimulation()->getSimTime());
                packet->setContextPointer(info);
                receivedPackets->insert(packet);
            }
        }
    }
    else {
        Packet *ipv4Packet = check_and_cast<Packet *>(outboundPackets->pop());
//        const auto& ipv4Header = ipv4Packet->peekAtFront<Ipv4Header>();
        Packet *liveIpv4Packet = packet;
//        const auto& liveIpv4Header = liveIpv4Packet->peekAtFront<Ipv4Header>();
        PacketDrillInfo *info = (PacketDrillInfo *)ipv4Packet->getContextPointer();
        if (verifyTime(static_cast<eventTime_t>(info->getTimeType()), info->getScriptTime(),
            info->getScriptTimeEnd(), info->getOffset(), getSimulation()->getSimTime(), "outbound packet") == STATUS_ERR)
        {
            throw cTerminationException("Packetdrill error: Packet arrived at the wrong time");
        }
        if (!compareDatagram(ipv4Packet, liveIpv4Packet)) {
            throw cTerminationException("Packetdrill error: Datagrams are not the same");
        }
        delete info;
        if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
            eventCounter++;
            scheduleEvent();
        }
        delete (PacketDrillInfo *)packet->getContextPointer();
        delete packet;
    }
}

void PacketDrillApp::socketClosed(TunSocket *socket)
{
    delete socketMap.removeSocket(socket);
}

void PacketDrillApp::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        handleTimer(msg);
    }
    else {
        if (!msg->arrivedOn("socketIn"))
            throw cRuntimeError("Message arrived on unknown gate %s", msg->getArrivalGate()->getFullName());

        // tunSocket must be checked before socketMap: PacketDrillApp funnels
        // TCP/UDP/SCTP/tun messages through the same "socketIn" gate, but
        // socketMap only holds TCP connection sockets, and
        // TcpSocket::belongsToSocket() unconditionally does
        // check_and_cast<Indication*>(msg) -- fatal on a raw tun data Packet.
        // Since a TCP connection is normally active whenever the tun app is
        // also receiving real (non-injected) traffic, socketMap.findSocketFor()
        // would otherwise crash on every such packet instead of ever reaching
        // the tunSocket branch below.
        if (tunSocket.belongsToSocket(msg)) {
            tunSocket.processMessage(msg);
            return;
        }
        ISocket *socket = socketMap.findSocketFor(msg);
        if (socket) {
            socket->processMessage(msg);
        }
        else if (udpSocket.belongsToSocket(msg)) {
            // received from UDP
            PacketDrillEvent *event = check_and_cast<PacketDrillEvent *>(script->getEventList()->get(eventCounter));
            if (verifyTime(event->getTimeType(), event->getEventTime(), event->getEventTimeEnd(),
                    event->getEventOffset(), getSimulation()->getSimTime(), "inbound packet") == STATUS_ERR)
            {
                delete msg;
                throw cTerminationException("Packetdrill error: Packet arrived at the wrong time");
            }
            udpSocket.processMessage(msg);
        }
        else if (tcpSocket.belongsToSocket(msg)) {
            tcpSocket.processMessage(msg);
        }
        else if (sctpSocket.belongsToSocket(msg)) {
            sctpSocket.processMessage(msg);
        }
    }
}

void PacketDrillApp::adjustTimes(PacketDrillEvent *event)
{
    simtime_t offset, offsetLastEvent;
    if (event->getTimeType() == ANY_TIME ||
        event->getTimeType() == RELATIVE_TIME ||
        event->getTimeType() == RELATIVE_RANGE_TIME)
    {
        offset = getSimulation()->getSimTime() - simStartTime;
        offsetLastEvent = (check_and_cast<PacketDrillEvent *>(script->getEventList()->get(eventCounter - 1)))->getEventTime() - simStartTime;
        offset = (offset.dbl() > offsetLastEvent.dbl()) ? offset : offsetLastEvent;
        event->setEventOffset(offset);
        event->setEventTime(event->getEventTime() + offset + simStartTime);
        if (event->getTimeType() == RELATIVE_RANGE_TIME) {
            event->setEventTimeEnd(event->getEventTimeEnd() + offset + simStartTime);
        }
    }
    else if (event->getTimeType() == ABSOLUTE_TIME) {
        event->setEventTime(event->getEventTime() + simStartTime);
    }
    else
        throw cRuntimeError("Unknown time type");
}

void PacketDrillApp::scheduleEvent()
{
    PacketDrillEvent *event = check_and_cast<PacketDrillEvent *>(script->getEventList()->get(eventCounter));
    event->setEventNumber(eventCounter);
    adjustTimes(event);
    eventTimer->setContextPointer(event);
    rescheduleAt(event->getEventTime(), eventTimer);
}

void PacketDrillApp::runEvent(PacketDrillEvent *event)
{
    char str[128];
    if (event->getType() == PACKET_EVENT) {
        Packet *pk = event->getPacket()->getInetPacket();
        if (event->getPacket()->getDirection() == DIRECTION_INBOUND) { // < injected packet, will go through the stack bottom up.
            auto packetByteLength = pk->getDataLength();
            auto ipHeader = pk->removeAtFront<Ipv4Header>();
            // remove lower layer paddings:
            ASSERT(B(ipHeader->getTotalLengthField()) >= ipHeader->getChunkLength());
            if (ipHeader->getTotalLengthField() < packetByteLength)
                pk->setBackOffset(B(ipHeader->getTotalLengthField()) - ipHeader->getChunkLength());

            if (ipHeader->getProtocolId() == IP_PROT_ICMP) {
                // An injected ICMP error carries a copy of OUR outbound
                // packet as its payload. The prebuilt copy has the
                // parse-time port pair -- stale after a multi-connection
                // script's per-socket local-port bump, which made INET route
                // the error to a DEFUNCT earlier connection (e.g. the
                // TIME_WAIT cookie-warmup conn) instead of the live one.
                // Re-stamp the embedded TCP header's ports like the plain-TCP
                // branch below does for its own header.
                auto icmpHeader = pk->removeAtFront<IcmpHeader>();
                if (pk->getDataLength() >= B(20) + B(8)) { // embedded IPv4 header + >=8B of TCP
                    auto embIpHeader = pk->removeAtFront<Ipv4Header>();
                    auto embTcpHeader = pk->removeAtFront<TcpHeader>();
                    embTcpHeader->setSrcPort(localPort);
                    embTcpHeader->setDestPort(remotePort);
                    // the quoted packet is OUR outbound: rebase its script-
                    // frame sequence onto the live ISN, so INET's quoted-seq
                    // window validation (RFC 5927) sees the intended
                    // in/out-of-window relation
                    embTcpHeader->setSequenceNo(embTcpHeader->getSequenceNo() + relSequenceOut);
                    pk->insertAtFront(embTcpHeader);
                    pk->insertAtFront(embIpHeader);
                }
                pk->insertAtFront(icmpHeader);
            }
            else if (protocol == IP_PROT_TCP) {
                auto tcpHeader = pk->removeAtFront<TcpHeader>();
                // stamp the CURRENT port pair: prebuilt packets carry the
                // parse-time ports, stale after a multi-connection script's
                // per-socket local-port bump (see syscallSocket)
                tcpHeader->setSrcPort(remotePort);
                tcpHeader->setDestPort(localPort);
                // Upstream packetdrill's tcpdump convention: a SYN's seq is the
                // absolute peer ISN (injected raw, remembered); every other
                // inbound packet's seq is RELATIVE to it (e.g. simple1's
                // "< . 1:1(0)" after "< S 1428932:..." must arrive at wire seq
                // 1428933). Zero for the common 0-based scripts.
                if (tcpHeader->getSynBit())
                    relSequenceIn = tcpHeader->getSequenceNo();
                else
                    tcpHeader->setSequenceNo(tcpHeader->getSequenceNo() + relSequenceIn);
                // tcpi_rcv_mss wire shadow: largest injected TCP payload
                {
                    int64_t pl = (B(ipHeader->getTotalLengthField()) - ipHeader->getChunkLength() - tcpHeader->getHeaderLength()).get<B>();
                    if (pl > (int64_t)maxInjectedPayload)
                        maxInjectedPayload = (uint32_t)pl;
                }
                // POLLRDHUP truth: Linux reports the half-close the moment the
                // FIN ARRIVES, even while undelivered data sits in the receive
                // queue -- INET's TCP_I_PEER_CLOSED indication is deferred
                // until the data is read, too late for a poll() right after
                // the FIN. The harness injected this FIN itself: record it.
                if (tcpHeader->getFinBit()) {
                    peerClosedSeen = true;
                    checkDeferredPollNow();
                }
                // TCPI_OPT_SYN_DATA wire shadow (see the header): a peer SYN
                // carrying data toward the DUT server; and a peer SYN-ACK
                // acking the DUT client's SYN data (ack rebasing happens just
                // below, so compare in the script frame here).
                {
                    int64_t payload = (B(ipHeader->getTotalLengthField()) - ipHeader->getChunkLength() - tcpHeader->getHeaderLength()).get<B>();
                    if (tcpHeader->getSynBit() && !tcpHeader->getAckBit() && payload > 0)
                        tfoShadowSynDataEndIn = tcpHeader->getSequenceNo() + 1 + payload;
                    if (tcpHeader->getSynBit() && tcpHeader->getAckBit() && tfoShadowSynDataEndOut != 0) {
                        uint32_t liveAck = tcpHeader->getAckNo() + relSequenceOut - scriptIsnOut;
                        if (!seqLess(liveAck, tfoShadowSynDataEndOut))
                            tfoSynDataAckedShadow = true;
                    }
                }
                // TX timestamping: a non-SYN ACK's number here is still in the DUT's
                // relative data space (script frame) -- exactly what pending TX-ACK
                // keys are measured in -- so fire SCM_TSTAMP_ACK for any key this ACK
                // covers BEFORE the number is rebased onto the live ISN below.
                if (tcpHeader->getAckBit() && !tcpHeader->getSynBit())
                    recordTxTimestampAck(tcpHeader->getAckNo());
                // ack: script acks the DUT's data relative to the DUT's script
                // ISN; on a SYN(-ACK) packet the script literal is absolute in
                // the script's own frame, so the declared script ISN is
                // subtracted before rebasing onto the live ISN.
                tcpHeader->setAckNo(tcpHeader->getAckNo() + relSequenceOut
                    - (tcpHeader->getSynBit() ? scriptIsnOut : 0));
                if (tcpHeader->getHeaderOptionArraySize() > 0) {
                    for (unsigned int i = 0; i < tcpHeader->getHeaderOptionArraySize(); i++) {
                        if (tcpHeader->getHeaderOption(i)->getKind() == TCPOPT_TIMESTAMP) {
                            // TSecr must echo the DUT's LIVE timestamp clock, which
                            // the script cannot know -- re-stamp it with the last
                            // TSval observed on a live outbound segment (peerTS),
                            // like upstream packetdrill's ecr remapping. The TSval
                            // is the scripted PEER's own clock and must be
                            // PRESERVED verbatim: the DUT stores it as ts_recent
                            // and echoes it back, and the script's outbound "ecr"
                            // assertions are written against these literals.
                            // (Previously the whole option was rebuilt with only
                            // ecr set, silently zeroing every injected TSval.)
                            auto *oldTs = check_and_cast<const TcpOptionTimestamp *>(tcpHeader->getHeaderOption(i));
                            TcpOptionTimestamp *option = new TcpOptionTimestamp();
                            option->setSenderTimestamp(oldTs->getSenderTimestamp());
                            // Map the script's ecr onto the live clock: a KNOWN
                            // script TSval maps to its recorded live value, an
                            // ecr matching the last outbound expectation's clock
                            // in general falls back to peerTS -- but an ecr the
                            // DUT never sent (a deliberate bad echo, e.g. 9999
                            // in synack-data TEST5) is injected RAW so the DUT
                            // can reject it like Linux does.
                            uint32_t scriptEcr = oldTs->getEchoedTimestamp();
                            if (scriptEcr == 0)
                                option->setEchoedTimestamp(0);
                            else if (scriptOutTsVals.empty() || scriptOutTsVals.count(scriptEcr))
                                option->setEchoedTimestamp(peerTS);
                            else
                                option->setEchoedTimestamp(scriptEcr);
                            tcpHeader->removeHeaderOption(i);
                            tcpHeader->setHeaderOption(i, option);
                        }
                        else if (auto *sackOpt = dynamic_cast<TcpOptionSack *>(tcpHeader->getHeaderOptionForUpdate(i))) {
                            // SACK blocks report ranges of the DUT's OWN sequence
                            // space, which the script writes relative to the DUT's
                            // ISN (packetdrill maps it to 0) -- shift them by the
                            // live ISN exactly like the ACK number above. Unshifted,
                            // a "sack 1001:2001" block lands below snd_una and INET
                            // rightly discards it as stale/D-SACK, so injected
                            // dupacks never arm fast retransmit and every loss
                            // -recovery script ends in an RTO instead.
                            for (unsigned int s = 0; s < sackOpt->getSackItemArraySize(); s++) {
                                auto& item = sackOpt->getSackItemForUpdate(s);
                                item.setStart(item.getStart() + relSequenceOut);
                                item.setEnd(item.getEnd() + relSequenceOut);
                            }
                        }
                        else if (tcpHeader->getSynBit() && tcpHeader->getAckBit()) {
                            // TFO cookie-cache mirror (see tfoCookieCached in the
                            // header): a SYN-ACK delivering a valid-length cookie
                            // makes INET cache it, so subsequent fastOpen connects
                            // will DEFER their SYN until the first send.
                            unsigned int fooLen = 0;
                            if (auto *fo = dynamic_cast<const TcpOptionTcpFastOpen *>(tcpHeader->getHeaderOption(i)))
                                fooLen = fo->getCookieArraySize();
                            else if (auto *foe = dynamic_cast<const TcpOptionTcpFastOpenExp *>(tcpHeader->getHeaderOption(i)))
                                fooLen = foe->getCookieArraySize();
                            if (fooLen >= 4 && fooLen <= 16)
                                tfoCookieCached = true;
                        }
                    }
                }
                pk->insertAtFront(tcpHeader);
                snprintf(str, sizeof(str), "inbound %d", eventCounter);
                pk->setName(str);
            }
            else if (protocol == IP_PROT_SCTP) {
                auto sctpHeader = pk->removeAtFront<SctpHeader>();
                sctpHeader->setVTag(peerVTag);
                int32_t noChunks = sctpHeader->getSctpChunksArraySize();
                for (int32_t cc = 0; cc < noChunks; cc++) {
                    SctpChunk *chunk = const_cast<SctpChunk *>(sctpHeader->getSctpChunks(cc));
                    unsigned char chunkType = chunk->getSctpChunkType();
                    switch (chunkType) {
                        case INIT: {
                            SctpInitChunk *init = check_and_cast<SctpInitChunk *>(chunk);
                            peerInStreams = init->getNoInStreams();
                            peerOutStreams = init->getNoOutStreams();
                            initPeerTsn = init->getInitTsn();
                            localVTag = init->getInitTag();
                            peerCumTsn = initPeerTsn - 1;
                            break;
                        }
                        case INIT_ACK: {
                            SctpInitAckChunk *initack = check_and_cast<SctpInitAckChunk *>(chunk);
                            localVTag = initack->getInitTag();
                            initPeerTsn = initack->getInitTsn();
                            peerCumTsn = initPeerTsn - 1;
                            break;
                        }
                        case COOKIE_ECHO: {
                            SctpCookieEchoChunk *cookieEcho = check_and_cast<SctpCookieEchoChunk *>(chunk);
                            int tempLength = cookieEcho->getByteLength();
                            peerCookie->setName("CookieEchoStateCookie");
                            cookieEcho->setStateCookie(peerCookie);
                            peerCookie = nullptr;
                            cookieEcho->setByteLength(SCTP_COOKIE_ACK_LENGTH + peerCookieLength);
                            int length = B(sctpHeader->getChunkLength()).get() - tempLength + cookieEcho->getByteLength();
                            sctpHeader->setChunkLength(B(length));
                            break;
                        }
                        case SACK: {
                            SctpSackChunk *sack = check_and_cast<SctpSackChunk *>(chunk);
                            sack->setCumTsnAck(sack->getCumTsnAck() + localDiffTsn);
                            if (sack->getNumGaps() > 0) {
                                for (int i = 0; i < sack->getNumGaps(); i++) {
                                    sack->setGapStart(i, sack->getGapStart(i) + sack->getCumTsnAck());
                                    sack->setGapStop(i, sack->getGapStop(i) + sack->getCumTsnAck());
                                }
                            }
                            if (sack->getNumDupTsns() > 0) {
                                for (int i = 0; i < sack->getNumDupTsns(); i++) {
                                    sack->setDupTsns(i, sack->getDupTsns(i) + localDiffTsn);
                                }
                            }
                            sctpHeader->setSctpChunks(cc, sack);
                            break;
                        }
                        case RE_CONFIG: {
                            SctpStreamResetChunk *reconfig = check_and_cast<SctpStreamResetChunk *>(chunk);
                            for (unsigned int i = 0; i < reconfig->getParametersArraySize(); i++) {
                                auto *parameter = const_cast<SctpParameter *>(reconfig->getParameters(i));
                                switch (parameter->getParameterType()) {
                                    case STREAM_RESET_RESPONSE_PARAMETER: {
                                        SctpStreamResetResponseParameter *param = check_and_cast<SctpStreamResetResponseParameter *>(parameter);
                                        param->setSrResSn(seqNumMap[param->getSrResSn()]);
                                        if (param->getReceiversNextTsn() != 0) {
                                            param->setReceiversNextTsn(param->getReceiversNextTsn() + localDiffTsn);
                                        }
                                        break;
                                    }
                                    case OUTGOING_RESET_REQUEST_PARAMETER: {
                                        auto *param = check_and_cast<SctpOutgoingSsnResetRequestParameter *>(parameter);
                                        if (findSeqNumMap(param->getSrResSn())) {
                                            param->setSrResSn(seqNumMap[param->getSrResSn()]);
                                        }
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
                pk->insertAtFront(sctpHeader);
                pk->setName("inboundSctp");
            }
            else {
                // other protocol
            }
            ipHeader->setTotalLengthField(ipHeader->getChunkLength() + pk->getDataLength());
            pk->insertAtFront(ipHeader);
            tunSocket.send(pk);
        }
        else if (event->getPacket()->getDirection() == DIRECTION_OUTBOUND) { // >
            // Find the first queued OUTBOUND IP datagram, skipping any app-layer
            // read data. A server that both ACKs a segment and delivers its
            // payload to the app queues BOTH into receivedPackets (the TCP-socket
            // data callback and the tun callback share the queue); only the IP
            // datagrams are outbound packets to compare -- app data (a bare
            // ByteCountChunk with no Ipv4Header) stays queued for
            // read()/recvfrom() to consume. Any IP datagram qualifies: SCTP and
            // UDP scripts' outbound expectations go through this same path, so
            // the predicate must not be TCP-only.
            Packet *livePacket = nullptr;
            for (cQueue::Iterator it(*receivedPackets); !it.end(); it++) {
                auto *p = dynamic_cast<Packet *>(check_and_cast<cPacket *>(*it));
                if (p && dynamicPtrCast<const Ipv4Header>(p->peekAtFront<Chunk>()) != nullptr) {
                    livePacket = p;
                    break;
                }
            }
            if (livePacket) {
                receivedPackets->remove(livePacket);
                if (pk && livePacket) {
                    PacketDrillInfo *liveInfo = (PacketDrillInfo *)livePacket->getContextPointer();
                    if (verifyTime(event->getTimeType(), event->getEventTime(),
                            event->getEventTimeEnd(), event->getEventOffset(), liveInfo->getLiveTime(),
                            "outbound packet") == STATUS_ERR)
                    {
                        throw cTerminationException("Packetdrill error: Timing error");
                    }
                    // takes ownership of both packets; may park pk as a GSO
                    // super-segment awaiting further live slices
                    startOutboundComparison(pk, livePacket);
                    // further slices may already be queued (INET emits its
                    // burst back-to-back before the script clock advances).
                    // receivedPackets can INTERLEAVE app-data deliveries with
                    // tun packets (e.g. unread TFO SYN payload sitting at the
                    // front for the whole script) -- iterate and consume tun
                    // slices in arrival order, leaving app data queued, same
                    // as consumeAppBytes() does in the other direction.
                    while (aggExpectedOutbound != nullptr) {
                        Packet *slice = nullptr;
                        for (cQueue::Iterator it(*receivedPackets); !it.end(); it++) {
                            auto *qpkt = dynamic_cast<Packet *>(*it);
                            if (qpkt && tcpPayloadLength(qpkt) >= 0) {
                                slice = qpkt;
                                break;
                            }
                        }
                        if (!slice)
                            break;
                        receivedPackets->remove(slice);
                        continueOutboundAggregation(slice);
                    }
                }
                else {
                    delete livePacket;
                    delete pk;
                }
            }
            else {
                if (protocol == IP_PROT_SCTP) {
                    const auto& ipHeader = pk->peekAtFront<Ipv4Header>();
                    const auto& sctpHeader = pk->peekDataAt<SctpHeader>(ipHeader->getChunkLength());
                    const SctpChunk *sctpChunk = sctpHeader->getSctpChunks(0);
                    if (sctpChunk->getSctpChunkType() == INIT) {
                        auto *init = check_and_cast<const SctpInitChunk *>(sctpChunk);
                        initLocalTsn = init->getInitTsn();
                        peerVTag = init->getInitTag();
                        localCumTsn = initLocalTsn - 1;
                        sctpSocket.setInboundStreams(init->getNoInStreams());
                        sctpSocket.setOutboundStreams(init->getNoOutStreams());
                    }
                    else if (sctpChunk->getSctpChunkType() == INIT_ACK) {
                        auto *initack = check_and_cast<const SctpInitAckChunk *>(sctpChunk);
                        initLocalTsn = initack->getInitTsn();
                        peerVTag = initack->getInitTag();
                        localCumTsn = initLocalTsn - 1;
                    }
                }
                PacketDrillInfo *info = new PacketDrillInfo("outbound");
                info->setScriptTime(event->getEventTime());
                info->setScriptTimeEnd(event->getEventTimeEnd());
                info->setOffset(event->getEventOffset());
                info->setTimeType(event->getTimeType());
                pk->setContextPointer(info);
                snprintf(str, sizeof(str), "outbound %d", eventCounter);
                pk->setName(str);
                outboundPackets->insert(pk);
            }
        }
        else
            throw cRuntimeError("Invalid direction");
    }
    else if (event->getType() == SYSCALL_EVENT) {
        EV_INFO << "syscallEvent: time_type = " << event->getTimeType() << " event time = " << event->getEventTime()
                << " end event time = " << event->getEventTimeEnd() << endl;
        // a blocking syscall's scripted end time ("+.09...0.14" -- the range
        // end lives in the SYSCALL spec's end_usecs, not the event time),
        // application-behavior ground truth consumed by syscallWrite's
        // writer-blocked marker; mapped to live time the same way the
        // blocking-poll window end is
        if (event->getSyscall()->end_usecs >= 0)
            currentSyscallEnd = SimTime(event->getSyscall()->end_usecs, SIMTIME_US)
                + event->getEventOffset() + simStartTime;
        runSystemCallEvent(event, event->getSyscall());
        currentSyscallEnd = -1;
    }
    else if (event->getType() == COMMAND_EVENT) {
        runCommandEvent(event);
        // same bounds guard as every other advancement site: a script whose
        // LAST event is a backtick command (e.g. a trailing sysctl restore)
        // must not walk past the event list (scheduleEvent() null-derefs)
        if (!eventTimer->isScheduled() && eventCounter < numEvents - 1) {
            eventCounter++;
            scheduleEvent();
        }
    }
    else if (event->getType() == CODE_EVENT) {
        runCodeEvent(event);
    }
}

void PacketDrillApp::runCommandEvent(PacketDrillEvent *event)
{
    // A timed backtick shell command. Real packetdrill hands the line to
    // /bin/sh; the only effect worth modeling for the simulated stack is a
    // sysctl assignment that changes TCP behavior for LATER connections
    // (INET's Tcp module reads its parameters per connection at open time,
    // which is also when Linux samples these). Everything else the corpus
    // uses in timed commands (nstat, tc qdisc, ip tcp_metrics flush, the
    // sysctl_restore tail script) is a no-op here. The key->parameter
    // mapping mirrors the preamble translation of tcp/sysctls.yaml in the packetdrill suite.
    const char *cmdline = event->getCommand() ? event->getCommand()->command_line : nullptr;
    if (!cmdline)
        return;
    cModule *tcpModule = getParentModule()->getSubmodule("tcp");
    // `ip tcp_metrics flush` drops the per-destination TFO cookie cache, which is
    // how a script re-arms the cookie-REQUEST path mid-run. Not a sysctl, so it
    // has to be matched on the command line rather than as a key=value token.
    // net.ipv4.tcp_fastopen_cookies is the Google-only knob the corpus tries
    // first for the same purpose, with the ip command as its `||` fallback --
    // treat either as the flush, since the fallback only runs when the sysctl is
    // absent (it is, on a generic kernel) and both mean the same thing here.
    std::string cmdstr(cmdline);
    if (cmdstr.find("tcp_metrics flush") != std::string::npos
        || cmdstr.find("tcp_fastopen_cookies") != std::string::npos)
    {
        auto *tcp = dynamic_cast<inet::tcp::Tcp *>(tcpModule);
        if (tcp) {
            tcp->clearFastOpenCookieCache();
            EV_INFO << "command event: Fast Open cookie cache flushed\n";
        }
        else
            EV_WARN << "command event: cannot flush the Fast Open cookie cache -- the tcp"
                       " sibling module is not an inet::tcp::Tcp\n";
    }
    // `ip route change <dst> ... mtu [lock] N`: the route under the LIVE connection
    // gained a new MTU, which is what lets RFC 4821 probing search higher. Unlike a
    // sysctl this affects the current connection, so it goes to the socket.
    if (cmdstr.find("ip route ") != std::string::npos) {
        std::smatch m;
        static const std::regex mtuRe("\\bmtu\\s+(?:lock\\s+)?([0-9]+)");
        if (std::regex_search(cmdstr, m, mtuRe) && tcpSocket.getState() != TcpSocket::NOT_BOUND) {
            int mtu = atoi(m[1].str().c_str());
            tcpSocket.setPathMtu(mtu);
            EV_INFO << "command event: path MTU <- " << mtu << "\n";
        }
    }
    std::istringstream tokens(cmdline);
    std::string token;
    while (tokens >> token) {
        size_t eq = token.find('=');
        if (eq == std::string::npos || eq == 0)
            continue;
        std::string key = token.substr(0, eq);
        std::string value = token.substr(eq + 1);
        // normalize /proc/sys/net/ipv4/x and net/ipv4/x to net.ipv4.x
        if (key.compare(0, 10, "/proc/sys/") == 0)
            key = key.substr(10);
        std::replace(key.begin(), key.end(), '/', '.');
        if (key.compare(0, 4, "net.") != 0)
            continue; // shell noise (redirections, flags), not a sysctl
        if (!tcpModule) {
            EV_WARN << "command event: no tcp sibling module, ignoring sysctl " << key << "\n";
            continue;
        }
        if (key == "net.ipv4.tcp_timestamps") {
            tcpModule->par("timestampSupport").setBoolValue(atoi(value.c_str()) != 0);
            EV_INFO << "command event: timestampSupport <- " << value << " for later connections\n";
        }
        else if (key == "net.ipv4.tcp_ecn" || key == "net.ipv4.tcp_ecn_option") {
            // Same enum as tcp/sysctls.yaml's preamble translation -- keep the two in
            // step. The corpus reaches here from the fastopen server tests, which
            // re-run the same scenario with ECN switched on mid-script and then
            // assert an ECN-setup SYN-ACK ("> SE.") on the next connection.
            if (key == "net.ipv4.tcp_ecn_option")
                tcpModule->par("accEcnOptionEnabled").setBoolValue(atoi(value.c_str()) != 0);
            else {
                static const char *const modes[] = { "off", "rfc3168", "passive", "accecn", "rfc3168", "accecn-passive" };
                long mode = strtol(value.c_str(), nullptr, 0);
                if (mode < 0 || mode >= (long)(sizeof(modes) / sizeof(modes[0]))) {
                    EV_WARN << "command event: unmodeled tcp_ecn value " << value << " ignored\n";
                    continue;
                }
                tcpModule->par("tcpEcnMode").setStringValue(modes[mode]);
            }
            EV_INFO << "command event: " << key << " <- " << value << " for later connections\n";
        }
        else if (key == "net.ipv4.tcp_fastopen_key") {
            // primary key only ("primary,backup" allowed by Linux)
            std::string primary = value.substr(0, value.find(','));
            tcpModule->par("fastopenKey").setStringValue(primary.c_str());
            EV_INFO << "command event: fastopenKey <- " << primary << "\n";
        }
        else if (key == "net.ipv4.tcp_fastopen") {
            // same bit interpretation as tcp/sysctls.yaml (0x2/0x400 deliberately
            // swapped from the kernel's nominal meaning -- see the mapping's
            // comment on modeling the per-listener TCP_FASTOPEN setsockopt)
            long bits = strtol(value.c_str(), nullptr, 0);
            tcpModule->par("fastopenClientEnabled").setBoolValue((bits & 0x1) != 0);
            tfoClientEnabled = (bits & 0x1) != 0;
            tcpModule->par("fastopenClientNoCookieRequired").setBoolValue((bits & 0x4) != 0);
            tfoNoCookieMode = (bits & 0x4) != 0; // mirror for the deferred-SYN kick predicate
            tcpModule->par("fastopenExpOptionEnabled").setBoolValue((bits & 0x2) != 0);
            tcpModule->par("fastopenServerEnabled").setBoolValue((bits & 0x400) != 0);
            tcpModule->par("fastopenAcceptWithoutCookie").setBoolValue((bits & 0x200) != 0);
            EV_INFO << "command event: fastopen params <- " << value << " for later connections\n";
        }
        else
            EV_WARN << "command event: unmodeled sysctl " << key << "=" << value << " ignored\n";
    }
}

void PacketDrillApp::handleTimer(cMessage *msg)
{
    switch (msg->getKind()) {
        case MSGKIND_START: {
            simStartTime = getSimulation()->getSimTime();
            simRelTime = simStartTime;
            if (script->parseScriptAndSetConfig(config, nullptr)) {
                delete msg;
                throw cRuntimeError("Error parsing the script");
            }
            numEvents = script->getEventList()->getLength();
            scheduleEvent();
            delete msg;
            break;
        }

        case MSGKIND_EVENT: {
            PacketDrillEvent *event = (PacketDrillEvent *)msg->getContextPointer();
            runEvent(event);
            // socketOptionsArrived_ is only ever set by the SCTP-specific
            // socketOptionsArrived() callback (SctpSocket::CallbackInterface).
            // For TCP/UDP scripts it never fires, so gating advancement on it
            // unconditionally stalled every non-SCTP script after its first
            // event. Only require it for SCTP.
            // aggExpectedOutbound != nullptr means a GSO super-segment is only
            // PARTIALLY matched (its expectation was already popped off
            // outboundPackets, so the queue-empty check alone is a lie): the
            // event counter must not advance past the aggregate, or the next
            // "> P." step consumes live slices that belong to the still-open
            // super-segment (seq expected N+agg, actual N).
            // A BLOCKED TCP read must not stop the script clock: real
            // packetdrill executes the event timeline in a separate thread
            // from the blocking syscall, so later events (e.g. the very
            // injection that will satisfy the read) keep firing and the read
            // completes asynchronously in socketDataArrived(TcpSocket).
            // Freezing on recvFromSet deadlocked every "read-then-inject"
            // script whose data event follows the blocking read
            // (basic-zero-payload's read stalled until the SYN-ACK rexmit).
            // UDP/SCTP keep the old serialized behavior.
            if (((protocol != IP_PROT_SCTP || socketOptionsArrived_) && (!recvFromSet || protocol == IP_PROT_TCP) && !codeEventPending &&
                    outboundPackets->getLength() == 0 && aggExpectedOutbound == nullptr) &&
                (!eventTimer->isScheduled() && eventCounter < numEvents - 1))
            {
                eventCounter++;
                scheduleEvent();
            }
            if (eventCounter >= numEvents - 1 && !codeEventPending && outboundPackets->getLength() == 0
                    && aggExpectedOutbound == nullptr && !eventTimer->isScheduled()) {
                if (!codeBlockBuffer.empty())
                    executeCodeBlocks();
                closeAllSockets();
                scriptComplete = true;
            }
            break;
        }

        case MSGKIND_WRITER_UNBLOCK:
            // the blocking write's scripted end time: the writer wrote its
            // last byte and returned -- it is no longer stalled on space
            tcpSocket.setWriterBlocked(false);
            break;

        case MSGKIND_POLL_DEFERRED:
            evaluateDeferredPoll();
            break;

        case MSGKIND_STATUS_REQUEST:
            // Fired an instant after runCodeEvent() so any same-instant inbound
            // packet has settled; now take the tcp_info snapshot.
            tcpSocket.requestStatus();
            break;

        default:
            throw cRuntimeError("Unknown message kind");
    }
}

void PacketDrillApp::closeAllSockets()
{
    // This function unconditionally builds and sends an SCTP ABORT chunk --
    // meaningful only for SCTP. Called generically (script finished / syscall
    // error) regardless of protocol; for TCP/UDP it was sending a stray SCTP
    // packet at the very end of every script, which the peer/stack answers
    // with an ICMP protocol-unreachable, which PacketDrillApp then compares
    // against whatever the script's next expectation was -- turning every
    // otherwise-correct TCP script into a spurious "Datagrams are not the
    // same" failure right at the end.
    if (protocol != IP_PROT_SCTP)
        return;
    Packet *pk = new Packet("IPCleanup");
    SctpAbortChunk *abortChunk = new SctpAbortChunk("Abort");
    abortChunk->setSctpChunkType(ABORT);
    abortChunk->setT_Bit(1);
    abortChunk->setByteLength(SCTP_ABORT_CHUNK_LENGTH);
    auto sctpmsg = makeShared<SctpHeader>();
    sctpmsg->setChunkLength(B(SCTP_COMMON_HEADER));
    sctpmsg->setSrcPort(remotePort);
    sctpmsg->setDestPort(localPort);
    sctpmsg->setVTag(peerVTag);
    pk->setName("SCTPCleanUp");
    sctpmsg->setChecksumOk(true);
    sctpmsg->setChecksumMode(crcMode);
    sctpmsg->appendSctpChunks(abortChunk);
    pk->insertAtFront(sctpmsg);
    auto ipv4Header = makeShared<Ipv4Header>();
    ipv4Header->setSrcAddress(remoteAddress.toIpv4());
    ipv4Header->setDestAddress(localAddress.toIpv4());
    ipv4Header->setIdentification(0);
    ipv4Header->setVersion(4);
    ipv4Header->setHeaderLength(IPv4_MIN_HEADER_LENGTH);
    ipv4Header->setProtocolId(IP_PROT_SCTP);
    ipv4Header->setTimeToLive(32);
    ipv4Header->setMoreFragments(0);
    ipv4Header->setDontFragment(0);
    ipv4Header->setFragmentOffset(0);
    ipv4Header->setTypeOfService(0);
    ipv4Header->setChecksumMode(crcMode);
    ipv4Header->setChecksum(0);
    ipv4Header->setTotalLengthField(ipv4Header->getChunkLength() + pk->getDataLength());
    pk->insertAtFront(ipv4Header);
    EV_DETAIL << "Send Abort to cleanup association." << endl;

    tunSocket.send(pk);
}

bool PacketDrillApp::findSeqNumMap(uint32_t num)
{
   return containsKey(seqNumMap, num);
}

void PacketDrillApp::runSystemCallEvent(PacketDrillEvent *event, struct syscall_spec *syscall)
{
    char *error = nullptr;
    const char *name = syscall->name;
    cQueue *args = new cQueue("systemCallEventQueue");
    int result = STATUS_OK;

    // Evaluate script symbolic expressions to get live numeric args for system calls.

    if (pd->evaluateExpressionList(syscall->arguments, args, &error)) {
        args->clear();
        delete args;
        delete syscall->arguments;
        free(syscall);
        free(error);
        return;
    }

    if (!strcmp(name, "socket")) {
        result = syscallSocket(syscall, args, &error);
    }
    else if (!strcmp(name, "bind")) {
        result = syscallBind(syscall, args, &error);
    }
    else if (!strcmp(name, "listen")) {
        result = syscallListen(syscall, args, &error);
    }
    else if (!strcmp(name, "write") || !strcmp(name, "send")) {
        result = syscallWrite(syscall, args, &error);
    }
    else if (!strcmp(name, "read") || !strcmp(name, "recv")) {
        result = syscallRead(event, syscall, args, &error);
    }
    else if (!strcmp(name, "sendto")) {
        result = syscallSendTo(syscall, args, &error);
    }
    else if (!strcmp(name, "recvfrom")) {
        result = syscallRecvFrom(event, syscall, args, &error);
    }
    else if (!strcmp(name, "close")) {
        result = syscallClose(syscall, args, &error);
    }
    else if (!strcmp(name, "shutdown")) {
        result = syscallShutdown(syscall, args, &error);
    }
    else if (!strcmp(name, "open")) {
        // File descriptors are not modeled; the framework's payloads are all
        // zeroes anyway, so open()'s only role (feeding sendfile) is inert.
        result = STATUS_OK;
    }
    else if (!strcmp(name, "sendfile")) {
        result = syscallSendFile(syscall, args, &error);
    }
    else if (!strcmp(name, "sendmsg")) {
        result = syscallSendMsg(syscall, args, &error);
    }
    else if (!strcmp(name, "recvmsg")) {
        result = syscallRecvMsg(event, syscall, args, &error);
    }
    else if (!strcmp(name, "epoll_create") || !strcmp(name, "epoll_create1")) {
        result = syscallEpollCreate(syscall, args, &error);
    }
    else if (!strcmp(name, "epoll_ctl")) {
        result = syscallEpollCtl(syscall, args, &error);
    }
    else if (!strcmp(name, "epoll_wait")) {
        result = syscallEpollWait(syscall, args, &error);
    }
    else if (!strcmp(name, "poll")) {
        result = syscallPoll(event, syscall, args, &error);
    }
    else if (!strcmp(name, "connect")) {
        result = syscallConnect(syscall, args, &error);
    }
    else if (!strcmp(name, "accept")) {
        result = syscallAccept(syscall, args, &error);
    }
    else if (!strcmp(name, "setsockopt")) {
        result = syscallSetsockopt(syscall, args, &error);
    }
    else if (!strcmp(name, "getsockopt")) {
        result = syscallGetsockopt(syscall, args, &error);
    }
    else if (!strcmp(name, "sctp_sendmsg")) {
        result = syscallSctpSendmsg(syscall, args, &error);
    }
    else if (!strcmp(name, "sctp_send")) {
        result = syscallSctpSend(syscall, args, &error);
    }
    else {
        EV_INFO << "System call %s not known (yet)." << name;
    }
    args->clear();
    delete args;
    delete syscall->arguments;
    free(syscall);
    if (result == STATUS_ERR) {
        EV_ERROR << event->getLineNumber() << ": runtime error in " << syscall->name << " call: " << error << endl;
        closeAllSockets();
        free(error);
    }
    return;
}

int PacketDrillApp::syscallSocket(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int type;
    PacketDrillExpression *exp;

    if (args->getLength() != 3) {
        return STATUS_ERR;
    }
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS)) {
        return STATUS_ERR;
    }
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || exp->getS32(&type, error)) {
        return STATUS_ERR;
    }
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&protocol, error)) {
        return STATUS_ERR;
    }

    switch (protocol) {
        case IP_PROT_UDP:
            udpSocket.setOutputGate(gate("socketOut"));
            udpSocket.bind(localPort);
            break;

        case IP_PROT_TCP:
            tcpSocket.setOutputGate(gate("socketOut"));
            tcpSocket.bind(localPort);
            break;
        case IP_PROT_SCTP:
            sctpSocket.setOutputGate(gate("socketOut"));
            sctpAssocId = sctpSocket.getSocketId();
            if (sctpSocket.getOutboundStreams() == -1) {
                sctpSocket.setOutboundStreams(par("outboundStreams"));
            }
            if (sctpSocket.getInboundStreams() == -1) {
                sctpSocket.setInboundStreams(par("inboundStreams"));
            }
            sctpSocket.bind(localAddress, localPort);
            break;
        default:
            throw cRuntimeError("Protocol type not supported for the socket system call");
    }

    return STATUS_OK;
}

int PacketDrillApp::syscallBind(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd;
    PacketDrillExpression *exp;

    if (args->getLength() != 3)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_UDP:
            break;

        case IP_PROT_TCP:
            if (tcpSocket.getState() == TcpSocket::NOT_BOUND) {
                tcpSocket.bind(localAddress, localPort);
            }
            break;
        case IP_PROT_SCTP:
            if (sctpSocket.getState() == SctpSocket::NOT_BOUND) {
                sctpSocket.bind(localAddress, localPort);
            }
            break;
        default:
            throw cRuntimeError("Protocol type not supported for the bind system call");
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallListen(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, backlog;
    PacketDrillExpression *exp;

    if (args->getLength() != 2)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || exp->getS32(&backlog, error))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_UDP:
            break;

        case IP_PROT_TCP:
            listenSet = true;
            tcpSocket.listenOnce();
            break;
        case IP_PROT_SCTP: {
            sctpSocket.listen(0, true, 0, true, script_fd);
            listenSet = true;
            break;
        }
        default:
            throw cRuntimeError("Protocol type not supported for the listen system call");
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallAccept(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_accepted_fd;
    if (!listenSet)
        return STATUS_ERR;

    PacketDrillExpression *exp = syscall->result;
    if (!exp || exp->getS32(&script_accepted_fd, error))
        return STATUS_ERR;
    if (establishedPending) {
        if (protocol == IP_PROT_TCP)
            tcpSocket.setState(TcpSocket::CONNECTED);
        else if (protocol == IP_PROT_SCTP)
            sctpSocket.setState(SctpSocket::CONNECTED);
        establishedPending = false;
        sctpSocket.accept(sctpAssocId, script_accepted_fd);
    }
    else {
        acceptSet = true;
    }

    return STATUS_OK;
}

int PacketDrillApp::syscallWrite(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, count;
    PacketDrillExpression *exp;

    if (args->getLength() > 4)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, error))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_TCP: {
            Packet *payload = new Packet("Write");
            payload->setByteLength(syscall->result->getNum());
            tcpSocket.send(payload);
            break;
        }
        case IP_PROT_SCTP: {
            Packet *cmsg = new Packet("AppData", SCTP_C_SEND_ORDERED);
            auto applicationData = makeShared<BytesChunk>();
            uint32_t sendBytes = syscall->result->getNum();
            std::vector<uint8_t> vec;
            vec.resize(sendBytes);
            for (uint32_t i = 0; i < sendBytes; i++)
                vec[i] = (bytesSent + i) & 0xFF;
            applicationData->setBytes(vec);
            applicationData->addTag<CreationTimeTag>()->setCreationTime(simTime());

            cmsg->insertAtBack(applicationData);
            auto sendCommand = cmsg->addTag<SctpSendReq>();
            sendCommand->setLast(true);
            sendCommand->setSocketId(-1);
            sendCommand->setSendUnordered(false);
            sendCommand->setSid(0);

            sctpSocket.send(cmsg);
            break;
        }
        default:
            EV_INFO << "Protocol not supported for this socket call";
            break;
    }

    return STATUS_OK;
}

int PacketDrillApp::syscallConnect(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd;
    PacketDrillExpression *exp;

    if (args->getLength() != 3)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_UDP:
            break;

        case IP_PROT_TCP:
            tcpSocket.connect(remoteAddress, remotePort);
            // tcpConnId is otherwise never assigned (stays at its -1 default),
            // so later syscalls (close, read, ...) tag their SocketReq with -1,
            // which Tcp interprets as "create a new connection" instead of
            // referencing this one. TcpSocket assigns connId synchronously in
            // connect(), so it is valid to read back immediately.
            tcpConnId = tcpSocket.getSocketId();
            break;
        case IP_PROT_SCTP: {
            sctpSocket.setTunInterface(tunInterfaceId);
            sctpSocket.connect(script_fd, remoteAddress, remotePort, 0, true);
            break;
        }
        default:
            throw cRuntimeError("Protocol type not supported for the connect system call");
    }

    return STATUS_OK;
}

int PacketDrillApp::syscallSetsockopt(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, level, optname;
    PacketDrillExpression *exp;

    args->setName("syscallSetsockopt");
    assert(protocol == IP_PROT_SCTP);
    if (args->getLength() != 5)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || exp->getS32(&level, error))
        return STATUS_ERR;
    if (level != IPPROTO_SCTP) {
        return STATUS_ERR;
    }
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&optname, error))
        return STATUS_ERR;

    exp = check_and_cast<PacketDrillExpression *>(args->get(3));

    if (syscall->result->getNum() == -1) {
        if (exp->getType() == EXPR_SCTP_RESET_STREAMS) {
            delete exp->getResetStreams()->srs_stream_list;
        }
        return STATUS_OK;
    }
    switch (exp->getType()) {
        case EXPR_SCTP_INITMSG: {
            struct sctp_initmsg_expr *initmsg = exp->getInitmsg();
            sctpSocket.setOutboundStreams(initmsg->sinit_num_ostreams->getNum());
            sctpSocket.setInboundStreams(initmsg->sinit_max_instreams->getNum());
            sctpSocket.setMaxInitRetrans(initmsg->sinit_max_attempts->getNum());
            sctpSocket.setMaxInitRetransTimeout(initmsg->sinit_max_init_timeo->getNum());
            if (sctpSocket.getInboundStreams() > 0)
                sctpSocket.setAppLimited(true);
            break;
        }
        case EXPR_SCTP_RTOINFO: {
            struct sctp_rtoinfo_expr *rtoinfo = exp->getRtoinfo();
            sctpSocket.setRtoInfo(rtoinfo->srto_initial->getNum() * 1.0 / 1000, rtoinfo->srto_max->getNum() * 1.0 / 1000, rtoinfo->srto_min->getNum() * 1.0 / 1000);
            free(rtoinfo);
            break;
        }
        case EXPR_SCTP_SACKINFO: {
            struct sctp_sack_info_expr *sackinfo = exp->getSackinfo();
            sctpSocket.setSackPeriod(sackinfo->sack_delay->getNum() * 1.0 / 1000);
            sctpSocket.setSackFrequency(sackinfo->sack_freq->getNum());
            break;
        }
        case EXPR_SCTP_PEER_ADDR_PARAMS: {
            struct sctp_paddrparams_expr *expr_params = exp->getPaddrParams();
            if (expr_params->spp_flags->getNum() & SPP_HB_DISABLE)
                sctpSocket.setEnableHeartbeats(false);
            else if (expr_params->spp_flags->getNum() & SPP_HB_ENABLE)
                sctpSocket.setEnableHeartbeats(true);
            if (expr_params->spp_hbinterval->getNum() > 0)
                sctpSocket.setHbInterval(expr_params->spp_hbinterval->getNum());
            if (expr_params->spp_pathmaxrxt->getNum() > 0)
                sctpSocket.setPathMaxRetrans(expr_params->spp_pathmaxrxt->getNum());
            break;
        }
        case EXPR_SCTP_ASSOCPARAMS: {
            struct sctp_assocparams_expr *assoc_params = exp->getAssocParams();
            sctpSocket.setAssocMaxRtx(assoc_params->sasoc_asocmaxrxt->getNum());
            break;
        }
        case EXPR_SCTP_RESET_STREAMS: {
            struct sctp_reset_streams_expr *rs = exp->getResetStreams();
            Message *cmsg = new Message("SCTP_C_STREAM_RESET", SCTP_C_STREAM_RESET);
            auto rinfo = cmsg->addTag<SctpResetReq>();
            rinfo->setSocketId(-1);
            rinfo->setFd(rs->srs_assoc_id->getNum());
            rinfo->setRemoteAddr(sctpSocket.getRemoteAddr());
            if (rs->srs_number_streams->getNum() > 0 && rs->srs_stream_list != nullptr) {
                rinfo->setStreamsArraySize(rs->srs_number_streams->getNum());
                cQueue *qu = rs->srs_stream_list->getList();
                uint16_t i = 0;
                for (cQueue::Iterator iter(*qu); !iter.end(); iter++, i++) {
                    rinfo->setStreams(i, check_and_cast<PacketDrillExpression *>(*iter)->getNum());
                    qu->remove((*iter));
                }
                qu->clear();
            }
            if (rs->srs_flags->getNum() == SCTP_STREAM_RESET_OUTGOING) {
                rinfo->setRequestType(RESET_OUTGOING);
            }
            else if (rs->srs_flags->getNum() == SCTP_STREAM_RESET_INCOMING) {
                rinfo->setRequestType(RESET_INCOMING);
            }
            else if (rs->srs_flags->getNum() == (SCTP_STREAM_RESET_OUTGOING | SCTP_STREAM_RESET_INCOMING)) {
                rinfo->setRequestType(RESET_BOTH);
            }
            sctpSocket.sendNotification(cmsg);
            delete rs->srs_assoc_id;
            delete rs->srs_flags;
            delete rs->srs_number_streams;
            delete rs->srs_stream_list;
            free(rs);
            break;
        }
        case EXPR_SCTP_ADD_STREAMS: {
            struct sctp_add_streams_expr *as = exp->getAddStreams();
            Message *cmsg = new Message("SCTP_C_ADD_STREAMS", SCTP_C_ADD_STREAMS);
            auto rinfo = cmsg->addTag<SctpResetReq>();
            rinfo->setSocketId(-1);
            rinfo->setFd(as->sas_assoc_id->getNum());
            rinfo->setRemoteAddr(sctpSocket.getRemoteAddr());
            if (as->sas_instrms->getNum() != 0 && as->sas_outstrms->getNum() != 0) {
                rinfo->setRequestType(ADD_BOTH);
                rinfo->setInstreams(as->sas_instrms->getNum());
                rinfo->setOutstreams(as->sas_outstrms->getNum());
            }
            else if (as->sas_instrms->getNum() != 0) {
                rinfo->setRequestType(ADD_INCOMING);
                rinfo->setInstreams(as->sas_instrms->getNum());
            }
            else if (as->sas_outstrms->getNum() != 0) {
                rinfo->setRequestType(ADD_OUTGOING);
                rinfo->setOutstreams(as->sas_outstrms->getNum());
            }
            sctpSocket.sendNotification(cmsg);
            delete as->sas_assoc_id;
            delete as->sas_instrms;
            delete as->sas_outstrms;
            free(as);
            break;
        }

        case EXPR_SCTP_ASSOCVAL:
            switch (optname) {
                case SCTP_MAX_BURST: {
                    struct sctp_assoc_value_expr *burstvalue = exp->getAssocval();
                    sctpSocket.setMaxBurst(burstvalue->assoc_value->getNum());
                    break;
                }
                case SCTP_MAXSEG: {
                    struct sctp_assoc_value_expr *assocvalue = exp->getAssocval();
                    sctpSocket.setFragPoint(assocvalue->assoc_value->getNum());
                    break;
                }
                case SCTP_ENABLE_STREAM_RESET: {
                    struct sctp_assoc_value_expr *assocvalue = exp->getAssocval();
                    sctpSocket.setStreamReset(assocvalue->assoc_value->getNum());
                    delete assocvalue->assoc_id;
                    delete assocvalue->assoc_value;
                    free(assocvalue);
                    break;
                }
                default:
                    printf("Option name %d of type EXPR_SCTP_ASSOCVAL not known\n", optname);
                    break;
            }
            break;
        case EXPR_LIST: {
            int value;

            if (!exp || exp->getType() != EXPR_LIST) {
                return STATUS_ERR;
            }
            if (exp->getList()->getLength() != 1) {
                printf("Expected [<integer>] but got multiple elements");
                return STATUS_ERR;
            }

            PacketDrillExpression *exp2 = check_and_cast<PacketDrillExpression *>(exp->getList()->pop());
            exp2->getS32(&value, error);
            switch (optname) {
                case SCTP_NODELAY:
                    sctpSocket.setNagle(value ? 0 : 1);
                    break;
                case SCTP_RESET_ASSOC: {
                    Message *cmsg = new Message("SCTP_C_STREAM_RESET", SCTP_C_RESET_ASSOC);
                    auto rinfo = cmsg->addTag<SctpResetReq>();
                    rinfo->setSocketId(-1);
                    rinfo->setFd(value);
                    rinfo->setRemoteAddr(sctpSocket.getRemoteAddr());
                    rinfo->setRequestType(SSN_TSN);
                    sctpSocket.sendNotification(cmsg);
                    break;
                }
            }
            break;
        }
        case EXPR_INTEGER:
            break;
        default:
            printf("Type %d not known\n", exp->getType());
            break;
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallGetsockopt(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, level, optname;
    PacketDrillExpression *exp;

    assert(protocol == IP_PROT_SCTP);
    if (args->getLength() != 5)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || exp->getS32(&level, error))
        return STATUS_ERR;
    if (level != IPPROTO_SCTP) {
        return STATUS_ERR;
    }
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&optname, error))
        return STATUS_ERR;

    exp = check_and_cast<PacketDrillExpression *>(args->get(3));
    switch (exp->getType()) {
        case EXPR_SCTP_STATUS: {
            struct sctp_status_expr *status = exp->getStatus();
            if (status->sstat_instrms->getType() != EXPR_ELLIPSIS)
                if (status->sstat_instrms->getNum() != sctpSocket.getInboundStreams()) {
                    printf("Number of Inbound Streams does not match\n");
                    return STATUS_ERR;
                }
            if (status->sstat_outstrms->getType() != EXPR_ELLIPSIS)
                if (status->sstat_outstrms->getNum() != sctpSocket.getOutboundStreams()) {
                    printf("Number of Outbound Streams does not match\n");
                    return STATUS_ERR;
                }
            break;
        }
        default: printf("Getsockopt option is not supported\n");
            break;
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallSendTo(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, count, flags;
    PacketDrillExpression *exp;

    if (args->getLength() != 6)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(3));
    if (!exp || exp->getS32(&flags, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(4));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(5));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;

    Packet *payload = new Packet("SendTo");
    payload->setByteLength(count);

    switch (protocol) {
        case IP_PROT_UDP:
            udpSocket.sendTo(payload, remoteAddress, remotePort);
            break;

        default:
            throw cRuntimeError("Protocol type not supported for this system call");
    }

    return STATUS_OK;
}

int PacketDrillApp::syscallSctpSendmsg(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, count;
    PacketDrillExpression *exp;
    uint32_t flags, ppid, ttl, context;
    uint16_t stream_no;

    if (args->getLength() != 10)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(3));
    /*ToDo: handle address parameter */
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(4));
    /*ToDo: handle tolen parameter */
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(5));
    if (!exp || exp->getU32(&ppid, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(6));
    if (!exp || exp->getU32(&flags, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(7));
    if (!exp || exp->getU16(&stream_no, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(8));
    if (!exp || exp->getU32(&ttl, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(9));
    if (!exp || exp->getU32(&context, error))
        return STATUS_ERR;

    Packet *cmsg = new Packet("AppData");
    uint32_t sendBytes = syscall->result->getNum();
    auto applicationData = makeShared<BytesChunk>();
    std::vector<uint8_t> vec;
    vec.resize(sendBytes);
    for (uint32_t i = 0; i < sendBytes; i++)
        vec[i] = (bytesSent + i) & 0xFF;
    applicationData->setBytes(vec);
    applicationData->addTag<CreationTimeTag>()->setCreationTime(simTime());
    cmsg->insertAtBack(applicationData);

    auto sendCommand = cmsg->addTag<SctpSendReq>();
    sendCommand->setLast(true);
    sendCommand->setSocketId(sctpAssocId);
    sendCommand->setSid(stream_no);
    sendCommand->setPpid(ppid);
    if (flags == SCTP_UNORDERED) {
        sendCommand->setSendUnordered(true);
    }

    sctpSocket.send(cmsg);
    return STATUS_OK;
}

int PacketDrillApp::syscallSctpSend(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, count;
    PacketDrillExpression *exp;
    uint16_t sid = 0, ssn = 0;
    uint32_t ppid = 0;

    if (syscall->result->getNum() == -1) {
        return STATUS_OK;
    }
    if (args->getLength() != 5)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, error))
        return STATUS_ERR;
    exp = check_and_cast<PacketDrillExpression *>(args->get(3));
    if (exp->getType() == EXPR_SCTP_SNDRCVINFO) {
        struct sctp_sndrcvinfo_expr *info = exp->getSndRcvInfo();
        ssn = info->sinfo_ssn->getNum();
        sid = info->sinfo_stream->getNum();
        ppid = info->sinfo_ppid->getNum();
    }
    Packet *cmsg = new Packet("AppData");
    auto applicationData = makeShared<BytesChunk>();
    uint32_t sendBytes = syscall->result->getNum();
    std::vector<uint8_t> vec;
    vec.resize(sendBytes);
    for (uint32_t i = 0; i < sendBytes; i++)
        vec[i] = (bytesSent + i) & 0xFF;
    applicationData->setBytes(vec);
    applicationData->addTag<CreationTimeTag>()->setCreationTime(simTime());
    cmsg->insertAtBack(applicationData);

    auto sendCommand = cmsg->addTag<SctpSendReq>();
    sendCommand->setLast(true);
    sendCommand->setSocketId(-1);
    sendCommand->setSid(sid);
    sendCommand->setPpid(ppid);
    sendCommand->setSsn(ssn);
    sendCommand->setSendUnordered(false);

    sctpSocket.send(cmsg);
    return STATUS_OK;
}

int PacketDrillApp::syscallRead(PacketDrillEvent *event, struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd, count;
    PacketDrillExpression *exp;

    if (syscall->result->getNum() == -1) {
        return STATUS_OK;
    }
    if (args->getLength() != 3)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, error))
        return STATUS_ERR;

    if ((expectedMessageSize = syscall->result->getNum()) > 0) {
        if (msgArrived || receivedPackets->getLength() > 0) {
            switch (protocol) {
                case IP_PROT_TCP: {
                    Request *msg = new Request("dataRequest", TCP_C_READ);
                    TcpCommand *tcpcmd = new TcpCommand();
                    msg->addTag<SocketReq>()->setSocketId(tcpConnId);
                    msg->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::tcp);
                    msg->setControlInfo(tcpcmd);
                    send(msg, "socketOut"); // send to TCP
                    break;
                }
                case IP_PROT_SCTP: {
                    Packet *pkt = new Packet("dataRequest", SCTP_C_RECEIVE);
                    auto sctpcmd = pkt->addTag<SctpSendReq>();
                    sctpcmd->setSocketId(sctpAssocId);
                    sctpcmd->setSid(0);
                    pkt->addTag<SocketReq>()->setSocketId(sctpAssocId);
                    pkt->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::sctp);
                    send(pkt, "socketOut"); // send to SCTP
                    break;
                }
                default:
                    EV_INFO << "Protocol not supported for this system call.";
                    break;
            }
            msgArrived = false;
            expectedMessageSize = syscall->result->getNum();
            recvFromSet = true;
            // send a receive request to TCP
        }
        else {
            recvFromSet = true;
        }
    }
    else {
        if (msgArrived) {
            outboundPackets->pop();
            msgArrived = false;
        }
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallRecvFrom(PacketDrillEvent *event, struct syscall_spec *syscall, cQueue *args, char **err)
{
    int script_fd, count, flags;
    PacketDrillExpression *exp;

    if (args->getLength() != 6)
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, err))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(1));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(2));
    if (!exp || exp->getS32(&count, err))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(3));
    if (!exp || exp->getS32(&flags, err))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(4));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;
    exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(5));
    if (!exp || (exp->getType() != EXPR_ELLIPSIS))
        return STATUS_ERR;

    if (msgArrived) {
        cPacket *msg = (receivedPackets->pop());
        msgArrived = false;
        recvFromSet = false;
        if (!(msg->getByteLength() == syscall->result->getNum())) {
            delete msg;
            throw cTerminationException("Packetdrill error: Wrong payload length");
        }
        PacketDrillInfo *info = (PacketDrillInfo *)msg->getContextPointer();
        if (verifyTime(event->getTimeType(), event->getEventTime(), event->getEventTimeEnd(),
                event->getEventOffset(), info->getLiveTime(), "inbound packet") == STATUS_ERR)
        {
            delete info;
            delete msg;
            return false;
        }
        delete info;
        delete msg;
    }
    else {
        expectedMessageSize = syscall->result->getNum();
        recvFromSet = true;
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallClose(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd;

    if (args->getLength() != 1)
        return STATUS_ERR;
    PacketDrillExpression *exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_UDP: {
            EV_DETAIL << "close UDP socket\n";
            udpSocket.close();
            break;
        }

        case IP_PROT_TCP: {
            Request *msg = new Request("close", TCP_C_CLOSE);
            TcpCommand *cmd = new TcpCommand();
            msg->addTag<SocketReq>()->setSocketId(tcpConnId);
            msg->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::tcp);
            msg->setControlInfo(cmd);
            send(msg, "socketOut"); // send to TCP
            break;
        }
        case IP_PROT_SCTP: {
            sctpSocket.close(script_fd);
            break;
        }
        default:
            EV_INFO << "Protocol " << protocol << " is not supported for this system call\n";
            break;
    }
    return STATUS_OK;
}

int PacketDrillApp::syscallShutdown(struct syscall_spec *syscall, cQueue *args, char **error)
{
    int script_fd;
    printf("syscallShutdown\n");
    if (args->getLength() != 2)
        return STATUS_ERR;
    PacketDrillExpression *exp = check_and_cast_nullable<PacketDrillExpression *>(args->get(0));
    if (!exp || exp->getS32(&script_fd, error))
        return STATUS_ERR;

    switch (protocol) {
        case IP_PROT_SCTP: {
            sctpSocket.shutdown(script_fd);
            break;
        }
        default:
            EV_INFO << "Protocol " << protocol << " is not supported for this system call\n";
            break;
    }
    return STATUS_OK;
}

void PacketDrillApp::finish()
{
    EV_INFO << "PacketDrillApp finished\n";
}

PacketDrillApp::~PacketDrillApp()
{
    cancelAndDelete(eventTimer);
    delete pd;
    delete receivedPackets;
    delete outboundPackets;
    delete config;
    delete script;
    socketMap.deleteSockets();
}

// Verify that something happened at the expected time.

int PacketDrillApp::verifyTime(enum eventTime_t timeType, simtime_t scriptTime, simtime_t scriptTimeEnd, simtime_t offset,
        simtime_t liveTime, const char *description)
{
    simtime_t expectedTime = scriptTime;
    simtime_t expectedTimeEnd = scriptTimeEnd;
    simtime_t actualTime = liveTime;
    simtime_t tolerance = SimTime(config->getToleranceUsecs(), SIMTIME_US);

    if (timeType == ANY_TIME) {
        return STATUS_OK;
    }

    if (timeType == ABSOLUTE_RANGE_TIME || timeType == RELATIVE_RANGE_TIME) {
        if (actualTime < (expectedTime - tolerance) || actualTime > (expectedTimeEnd + tolerance)) {
            if (timeType == ABSOLUTE_RANGE_TIME) {
                EV_INFO << "timing error: expected " << description << " in time range " << scriptTime << " ~ "
                        << scriptTimeEnd << " sec, but happened at " << actualTime << " sec" << endl;
            }
            else if (timeType == RELATIVE_RANGE_TIME) {
                EV_INFO << "timing error: expected " << description << " in relative time range +"
                        << scriptTime - offset << " ~ " << scriptTimeEnd - offset << " sec, but happened at +"
                        << actualTime - offset << " sec" << endl;
            }
            return STATUS_ERR;
        }
        else {
            return STATUS_OK;
        }
    }

    if ((actualTime < (expectedTime - tolerance)) || (actualTime > (expectedTime + tolerance))) {
        EV_INFO << "timing error: expected " << description << " at " << scriptTime << " sec, but happened at "
                << actualTime << " sec" << endl;
        return STATUS_ERR;
    }
    else {
        return STATUS_OK;
    }
}

bool PacketDrillApp::compareDatagram(Packet *storedPacket, Packet *livePacket)
{
    const auto& storedDatagram = storedPacket->peekAtFront<Ipv4Header>();
    const auto& liveDatagram = livePacket->peekAtFront<Ipv4Header>();

//    if (!(storedDatagram->getSrcAddress() == liveDatagram->getSrcAddress())) {
//        return false;
//    }
    std::cout << __LINE__ << endl;
    if (!(storedDatagram->getDestAddress() == liveDatagram->getDestAddress())) {
        return false;
    }
    if (!(storedDatagram->getProtocolId() == liveDatagram->getProtocolId())) {
        return false;
    }
    if (!(storedDatagram->getTimeToLive() == liveDatagram->getTimeToLive())) {
        return false;
    }
    if (!(storedDatagram->getIdentification() == liveDatagram->getIdentification())) {
        return false;
    }
    if (!(storedDatagram->getMoreFragments() == liveDatagram->getMoreFragments())) {
        return false;
    }
    if (!(storedDatagram->getDontFragment() == liveDatagram->getDontFragment())) {
        return false;
    }
    if (!(storedDatagram->getFragmentOffset() == liveDatagram->getFragmentOffset())) {
        return false;
    }
    if (!(storedDatagram->getTypeOfService() == liveDatagram->getTypeOfService())) {
        return false;
    }
    if (!(storedDatagram->getHeaderLength() == liveDatagram->getHeaderLength())) {
        return false;
    }
    switch (storedDatagram->getProtocolId()) {
        case IP_PROT_UDP: {
            const auto& storedUdp = storedPacket->peekDataAt<UdpHeader>(storedDatagram->getChunkLength());
            const auto& liveUdp = livePacket->peekDataAt<UdpHeader>(liveDatagram->getChunkLength());
            if (!(compareUdpHeader(storedUdp, liveUdp))) {
                return false;
            }
            break;
        }

        case IP_PROT_TCP: {
            const auto& storedTcp = storedPacket->peekDataAt<TcpHeader>(storedDatagram->getChunkLength());
            const auto& liveTcp = livePacket->peekDataAt<TcpHeader>(liveDatagram->getChunkLength());
            if (storedTcp->getSynBit()) { // SYN was sent. Store the sequence number for comparisons
                relSequenceOut = liveTcp->getSequenceNo();
            }
            if (storedTcp->getSynBit() && storedTcp->getAckBit()) {
                peerWindow = liveTcp->getWindow();
            }
            if (!(compareTcpHeader(storedTcp, liveTcp))) {
                return false;
            }
            break;
        }
        case IP_PROT_SCTP: {
            const auto& storedSctp = storedPacket->peekDataAt<SctpHeader>(storedDatagram->getChunkLength());
            const auto& liveSctp = livePacket->peekDataAt<SctpHeader>(liveDatagram->getChunkLength());
            if (!(compareSctpPacket(storedSctp, liveSctp))) {
                EV_DETAIL << "SCTP packets are not the same" << endl;
                return false;
            }
            break;
        }
        default:
            EV_INFO << "Transport protocol %d is not supported yet" << storedDatagram->getProtocolId();
            break;
    }
    return true;
}

bool PacketDrillApp::compareUdpHeader(const Ptr<const UdpHeader>& storedUdp, const Ptr<const UdpHeader>& liveUdp)
{
    return storedUdp->getSourcePort() == liveUdp->getSourcePort()
        && storedUdp->getDestinationPort() == liveUdp->getDestinationPort()
        && storedUdp->getTotalLengthField() == liveUdp->getTotalLengthField();
}

bool PacketDrillApp::compareTcpHeader(const Ptr<const TcpHeader>& storedTcp, const Ptr<const TcpHeader>& liveTcp)
{
    if (!(storedTcp->getSrcPort() == liveTcp->getSrcPort())) {
        return false;
    }
    if (!(storedTcp->getDestPort() == liveTcp->getDestPort())) {
        return false;
    }
    if (!(storedTcp->getSequenceNo() + relSequenceOut == liveTcp->getSequenceNo())) {
        return false;
    }
    if (!(storedTcp->getAckNo() == liveTcp->getAckNo())) {
        return false;
    }
    if (!(storedTcp->getUrgBit() == liveTcp->getUrgBit()) || !(storedTcp->getAckBit() == liveTcp->getAckBit()) ||
        !(storedTcp->getPshBit() == liveTcp->getPshBit()) || !(storedTcp->getRstBit() == liveTcp->getRstBit()) ||
        !(storedTcp->getSynBit() == liveTcp->getSynBit()) || !(storedTcp->getFinBit() == liveTcp->getFinBit()))
    {
        return false;
    }
    if (!(storedTcp->getUrgentPointer() == liveTcp->getUrgentPointer())) {
        return false;
    }

    if (storedTcp->getHeaderOptionArraySize() > 0 || liveTcp->getHeaderOptionArraySize()) {
        EV_DETAIL << "Options present";
        if (storedTcp->getHeaderOptionArraySize() == 0) {
            return true;
        }
        if (storedTcp->getHeaderOptionArraySize() != liveTcp->getHeaderOptionArraySize()) {
//            const TcpOption *liveOption;
//            for (unsigned int i = 0; i < liveTcp->getHeaderOptionArraySize(); i++) {
//                liveOption = liveTcp->getHeaderOption(i);
//            }
            return false;
        }
        else {
            const TcpOption *storedOption, *liveOption;
            for (unsigned int i = 0; i < storedTcp->getHeaderOptionArraySize(); i++) {
                storedOption = storedTcp->getHeaderOption(i);
                liveOption = liveTcp->getHeaderOption(i);
                if (storedOption->getKind() == liveOption->getKind()) {
                    switch (storedOption->getKind()) {
                        case TCPOPTION_END_OF_OPTION_LIST:
                        case TCPOPTION_NO_OPERATION:
                            if (!(storedOption->getLength() == liveOption->getLength())) {
                                return false;
                            }
                            break;
                        case TCPOPTION_SACK_PERMITTED:
                            if (!(storedOption->getLength() == liveOption->getLength() && storedOption->getLength() == 2)) {
                                return false;
                            }
                            break;
                        case TCPOPTION_WINDOW_SCALE:
                            if (!(storedOption->getLength() == liveOption->getLength() && storedOption->getLength() == 3 &&
                                  check_and_cast<const TcpOptionWindowScale *>(storedOption)->getWindowScale()
                                  == check_and_cast<const TcpOptionWindowScale *>(liveOption)->getWindowScale()))
                            {
                                return false;
                            }
                            break;
                        case TCPOPTION_SACK:
                            if (!(storedOption->getLength() == liveOption->getLength() &&
                                  storedOption->getLength() > 2 && (storedOption->getLength() % 8) == 2 &&
                                  check_and_cast<const TcpOptionSack *>(storedOption)->getSackItemArraySize()
                                  == check_and_cast<const TcpOptionSack *>(liveOption)->getSackItemArraySize()))
                            {
                                return false;
                            }
                            break;
                        case TCPOPTION_TIMESTAMP:
                            if (!(storedOption->getLength() == liveOption->getLength() && storedOption->getLength() == 10 &&
                                  check_and_cast<const TcpOptionTimestamp *>(storedOption)->getSenderTimestamp()
                                  == check_and_cast<const TcpOptionTimestamp *>(liveOption)->getSenderTimestamp()))
                            {
                                return false;
                            }
                            break;
                        default:
                            EV_INFO << "TCP Option type=" << storedOption->getKind() << " not supported";
                            break;
                    }
                }
                else {
                    EV_INFO << "Wrong sequence or option kind not present";
                    return false;
                }
            }
        }
    }
    return true;
}

bool PacketDrillApp::compareSctpPacket(const Ptr<const SctpHeader>& storedSctp, const Ptr<const SctpHeader>& liveSctp)
{
    if (!(storedSctp->getSrcPort() == liveSctp->getSrcPort())) {
        return false;
    }
    if (!(storedSctp->getDestPort() == liveSctp->getDestPort())) {
        return false;
    }
    if (!(storedSctp->getSctpChunksArraySize() == liveSctp->getSctpChunksArraySize())) {
        return false;
    }

    const uint32_t numberOfChunks = storedSctp->getSctpChunksArraySize();
    for (uint32_t i = 0; i < numberOfChunks; i++) {
        const SctpChunk *storedHeader = storedSctp->getSctpChunks(i);
        const SctpChunk *liveHeader = liveSctp->getSctpChunks(i);
        if (!(storedHeader->getSctpChunkType() == liveHeader->getSctpChunkType())) {
            return false;
        }
        const uint8_t type = storedHeader->getSctpChunkType();

        if ((type != INIT && type != INIT_ACK) && type != ABORT && (liveSctp->getVTag() != localVTag)) {
            EV_DETAIL << " VTag " << liveSctp->getVTag() << " incorrect. Should be " << localVTag << " peerVTag="
                      << peerVTag << endl;
            return false;
        }

        switch (type) {
            case DATA: {
                auto *storedDataChunk = check_and_cast<const SctpDataChunk *>(storedHeader);
                auto *liveDataChunk = check_and_cast<const SctpDataChunk *>(liveHeader);
                if (!(compareDataPacket(storedDataChunk, liveDataChunk))) {
                    EV_DETAIL << "DATA chunks are not the same" << endl;
                    return false;
                }
                break;
            }
            case INIT: {
                auto *storedInitChunk = check_and_cast<const SctpInitChunk *>(storedHeader);
                auto *liveInitChunk = check_and_cast<const SctpInitChunk *>(liveHeader);
                if (!(compareInitPacket(storedInitChunk, liveInitChunk))) {
                    EV_DETAIL << "INIT chunks are not the same" << endl;
                    return false;
                }
                break;
            }
            case INIT_ACK: {
                auto *storedInitAckChunk = check_and_cast<const SctpInitAckChunk *>(storedHeader);
                auto *liveInitAckChunk = check_and_cast<const SctpInitAckChunk *>(liveHeader);
                if (!(compareInitAckPacket(storedInitAckChunk, liveInitAckChunk))) {
                    EV_DETAIL << "INIT-ACK chunks are not the same" << endl;
                    return false;
                }
                break;
            }
            case SACK: {
                auto *storedSackChunk = check_and_cast<const SctpSackChunk *>(storedHeader);
                auto *liveSackChunk = check_and_cast<const SctpSackChunk *>(liveHeader);
                if (!(compareSackPacket(storedSackChunk, liveSackChunk))) {
                    EV_DETAIL << "SACK chunks are not the same" << endl;
                    return false;
                }
                break;
            }
            case COOKIE_ECHO: {
                auto *storedCookieEchoChunk = check_and_cast<const SctpCookieEchoChunk *>(storedHeader);
                if (!(storedCookieEchoChunk->getFlags() & FLAG_CHUNK_VALUE_NOCHECK))
                    printf("COOKIE_ECHO chunks should be compared\n");
                else
                    printf("Do not check cookie echo chunks\n");
                break;
            }
            case SHUTDOWN: {
                auto *storedShutdownChunk = check_and_cast<const SctpShutdownChunk *>(storedHeader);
                auto *liveShutdownChunk = check_and_cast<const SctpShutdownChunk *>(liveHeader);
                if (!(storedShutdownChunk->getFlags() & FLAG_SHUTDOWN_CHUNK_CUM_TSN_NOCHECK)) {
                    if (!(storedShutdownChunk->getCumTsnAck() == liveShutdownChunk->getCumTsnAck())) {
                        EV_DETAIL << "SHUTDOWN chunks are not the same" << endl;
                        return false;
                    }
                }
                break;
            }
            case SHUTDOWN_COMPLETE: {
                auto *storedShutdownCompleteChunk = check_and_cast<const SctpShutdownCompleteChunk *>(storedHeader);
                auto *liveShutdownCompleteChunk = check_and_cast<const SctpShutdownCompleteChunk *>(liveHeader);
                if (!(storedShutdownCompleteChunk->getFlags() & FLAG_CHUNK_FLAGS_NOCHECK))
                    if (!(storedShutdownCompleteChunk->getTBit() == liveShutdownCompleteChunk->getTBit())) {
                        EV_DETAIL << "SHUTDOWN-COMPLETE chunks are not the same" << endl;
                        return false;
                    }
                break;
            }
            case ABORT: {
                auto *storedAbortChunk = check_and_cast<const SctpAbortChunk *>(storedHeader);
                auto *liveAbortChunk = check_and_cast<const SctpAbortChunk *>(liveHeader);
                if (!(storedAbortChunk->getFlags() & FLAG_CHUNK_FLAGS_NOCHECK))
                    if (!(storedAbortChunk->getT_Bit() == liveAbortChunk->getT_Bit())) {
                        EV_DETAIL << "ABORT chunks are not the same" << endl;
                        return false;
                    }
                break;
            }
            case ERRORTYPE: {
                auto *storedErrorChunk = check_and_cast<const SctpErrorChunk *>(storedHeader);
                auto *liveErrorChunk = check_and_cast<const SctpErrorChunk *>(liveHeader);
                if (!(storedErrorChunk->getParametersArraySize() == liveErrorChunk->getParametersArraySize())) {
                    return false;
                }
                if (storedErrorChunk->getParametersArraySize() > 0) {
                    // Only Cause implemented so far.
                    auto *storedcause = check_and_cast<const SctpSimpleErrorCauseParameter *>(storedErrorChunk->getParameters(0));
                    auto *livecause = check_and_cast<const SctpSimpleErrorCauseParameter *>(liveErrorChunk->getParameters(0));
                    if (!(storedcause->getValue() == livecause->getValue())) {
                        return false;
                    }
                }
                break;
            }
            case HEARTBEAT: {
                auto *heartbeatChunk = check_and_cast<const SctpHeartbeatChunk *>(liveHeader);
                peerHeartbeatTime = heartbeatChunk->getTimeField();
                break;
            }
            case COOKIE_ACK:
            case SHUTDOWN_ACK:
            case HEARTBEAT_ACK:
                break;
            case RE_CONFIG: {
                auto *liveReconfigChunk = check_and_cast<const SctpStreamResetChunk *>(liveHeader);
//                liveReconfigChunk->setName("livereconfig");          //FIXME Why???
                auto *storedReconfigChunk = check_and_cast<const SctpStreamResetChunk *>(storedHeader);
                if (!(compareReconfigPacket(storedReconfigChunk, liveReconfigChunk))) {
                    EV_DETAIL << "RECONFIG chunks are not the same" << endl;
                    return false;
                }
                break;
            }
            default:
                printf("type %d not implemented\n", type);
                break;
        }
    }
    return true;
}

bool PacketDrillApp::compareDataPacket(const SctpDataChunk *storedDataChunk, const SctpDataChunk *liveDataChunk)
{
    uint32_t flags = storedDataChunk->getFlags();
    if (!(flags & FLAG_CHUNK_LENGTH_NOCHECK))
        if (storedDataChunk->getByteLength() != liveDataChunk->getByteLength())
            return false;

    if (!(flags & FLAG_CHUNK_FLAGS_NOCHECK)) {
        if (!(storedDataChunk->getBBit() == liveDataChunk->getBBit()))
            return false;
        if (!(storedDataChunk->getEBit() == liveDataChunk->getEBit()))
            return false;
    }
    if (!(flags & FLAG_DATA_CHUNK_TSN_NOCHECK))
        if (!(storedDataChunk->getTsn() + localDiffTsn == liveDataChunk->getTsn()))
            return false;
    if (!(flags & FLAG_DATA_CHUNK_SID_NOCHECK))
        if (!(storedDataChunk->getSid() == liveDataChunk->getSid()))
            return false;
    if (!(flags & FLAG_DATA_CHUNK_SSN_NOCHECK))
        if (!(storedDataChunk->getSsn() == liveDataChunk->getSsn()))
            return false;
    if (!(flags & FLAG_DATA_CHUNK_PPID_NOCHECK))
        if (!(storedDataChunk->getPpid() == liveDataChunk->getPpid()))
            return false;

    return true;
}

bool PacketDrillApp::compareInitPacket(const SctpInitChunk *storedInitChunk, const SctpInitChunk *liveInitChunk)
{
    uint32_t flags = storedInitChunk->getFlags();
    peerVTag = liveInitChunk->getInitTag();
    localDiffTsn = liveInitChunk->getInitTsn() - initLocalTsn;
    initPeerTsn = liveInitChunk->getInitTsn();
    localCumTsn = initPeerTsn - 1;
    peerCumTsn = initLocalTsn - 1;

    if (!(flags & FLAG_INIT_CHUNK_TSN_NOCHECK))
        if (!(storedInitChunk->getInitTsn() + localDiffTsn == liveInitChunk->getInitTsn()))
            return false;
    if (!(flags & FLAG_INIT_CHUNK_A_RWND_NOCHECK))
        if (!(storedInitChunk->getA_rwnd() == liveInitChunk->getA_rwnd()))
            return false;
    peerInStreams = liveInitChunk->getNoInStreams();
    peerOutStreams = liveInitChunk->getNoOutStreams();
    if (!(flags & FLAG_INIT_CHUNK_OS_NOCHECK))
        if (!(storedInitChunk->getNoOutStreams() == liveInitChunk->getNoOutStreams()))
            return false;
    if (!(flags & FLAG_INIT_CHUNK_IS_NOCHECK))
        if (!(storedInitChunk->getNoInStreams() == liveInitChunk->getNoInStreams()))
            return false;

    return true;
}

bool PacketDrillApp::compareInitAckPacket(const SctpInitAckChunk *storedInitAckChunk, const SctpInitAckChunk *liveInitAckChunk)
{
    uint32_t flags = storedInitAckChunk->getFlags();
    peerVTag = liveInitAckChunk->getInitTag();
    localDiffTsn = liveInitAckChunk->getInitTsn() - initLocalTsn;
    initPeerTsn = liveInitAckChunk->getInitTsn();
    localCumTsn = initPeerTsn - 1;
    peerCumTsn = initLocalTsn - 1;
    if (!(flags & FLAG_INIT_ACK_CHUNK_A_RWND_NOCHECK))
        if (!(storedInitAckChunk->getA_rwnd() == liveInitAckChunk->getA_rwnd()))
            return false;
    if (!(flags & FLAG_INIT_ACK_CHUNK_OS_NOCHECK))
        if (!(min(storedInitAckChunk->getNoOutStreams(), peerInStreams) == liveInitAckChunk->getNoOutStreams()))
            return false;
    if (!(flags & FLAG_INIT_ACK_CHUNK_IS_NOCHECK))
        if (!(min(storedInitAckChunk->getNoInStreams(), peerOutStreams) == liveInitAckChunk->getNoInStreams()))
            return false;
    if (!(flags & FLAG_INIT_ACK_CHUNK_TSN_NOCHECK))
        if (!(storedInitAckChunk->getInitTsn() + localDiffTsn == liveInitAckChunk->getInitTsn()))
            return false;
    peerCookie = CHK(liveInitAckChunk->getStateCookie())->dup(); // FIXME hack: dup() called for generate a mutable copy
    peerCookieLength = peerCookie->getLength();
    return true;
}

bool PacketDrillApp::compareReconfigPacket(const SctpStreamResetChunk *storedReconfigChunk, const SctpStreamResetChunk *liveReconfigChunk)
{
    bool found = false;

    uint32_t flags = storedReconfigChunk->getFlags();
    if (!(storedReconfigChunk->getParametersArraySize() == liveReconfigChunk->getParametersArraySize())) {
        return false;
    }
    for (unsigned int i = 0; i < storedReconfigChunk->getParametersArraySize(); i++) {
        auto *storedParameter = check_and_cast<const SctpParameter *>(storedReconfigChunk->getParameters(i));
        const SctpParameter *liveParameter = nullptr;
        found = false;
        switch (storedParameter->getParameterType()) {
            case OUTGOING_RESET_REQUEST_PARAMETER: {
                auto *storedoutparam = check_and_cast<const SctpOutgoingSsnResetRequestParameter *>(storedParameter);
                for (unsigned int j = 0; j < liveReconfigChunk->getParametersArraySize(); j++) {
                    liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(j));
                    if (liveParameter->getParameterType() != OUTGOING_RESET_REQUEST_PARAMETER)
                        continue;
                    else {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
                auto *liveoutparam = check_and_cast<const SctpOutgoingSsnResetRequestParameter *>(liveParameter);
                if (seqNumMap[storedoutparam->getSrReqSn()] == 0) {
                    seqNumMap[storedoutparam->getSrReqSn()] = liveoutparam->getSrReqSn();
                }
                else if (!(flags & FLAG_RECONFIG_REQ_SN_NOCHECK))
                    if (!(seqNumMap[storedoutparam->getSrReqSn()] == liveoutparam->getSrReqSn())) {
                        return false;
                    }
                if (seqNumMap[storedoutparam->getSrResSn()] == 0) {
                    seqNumMap[storedoutparam->getSrResSn()] = liveoutparam->getSrResSn();
                }
                if (!(flags & FLAG_RECONFIG_LAST_TSN_NOCHECK))
                    if (!(storedoutparam->getLastTsn() + localDiffTsn == liveoutparam->getLastTsn()))
                        return false;
                if (!(storedoutparam->getStreamNumbersArraySize() == liveoutparam->getStreamNumbersArraySize()))
                    return false;
                if (storedoutparam->getStreamNumbersArraySize() > 0) {
                    for (uint16_t i = 0; i < storedoutparam->getStreamNumbersArraySize(); i++) {
                        if (!(storedoutparam->getStreamNumbers(i) == liveoutparam->getStreamNumbers(i)))
                            return false;
                    }
                }
                break;
            }
            case INCOMING_RESET_REQUEST_PARAMETER: {
                found = false;
                auto *storedinparam = check_and_cast<const SctpIncomingSsnResetRequestParameter *>(storedParameter);
                for (unsigned int j = 0; j < liveReconfigChunk->getParametersArraySize(); j++) {
                    liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(j));
                    if (liveParameter->getParameterType() != INCOMING_RESET_REQUEST_PARAMETER)
                        continue;
                    else {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
                auto *liveinparam = check_and_cast<const SctpIncomingSsnResetRequestParameter *>(liveParameter);
                if (seqNumMap[storedinparam->getSrReqSn()] == 0) {
                    seqNumMap[storedinparam->getSrReqSn()] = liveinparam->getSrReqSn();
                }
                else if (!(seqNumMap[storedinparam->getSrReqSn()] == liveinparam->getSrReqSn())) {
                    return false;
                }
                if (!(storedinparam->getStreamNumbersArraySize() == liveinparam->getStreamNumbersArraySize()))
                    return false;
                if (storedinparam->getStreamNumbersArraySize() > 0) {
                    for (uint16_t i = 0; i < storedinparam->getStreamNumbersArraySize(); i++) {
                        if (!(storedinparam->getStreamNumbers(i) == liveinparam->getStreamNumbers(i)))
                            return false;
                    }
                }
                break;
            }
            case STREAM_RESET_RESPONSE_PARAMETER: {
                auto *storedresparam = check_and_cast<const SctpStreamResetResponseParameter *>(storedParameter);
                liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(i));
                if (liveParameter->getParameterType() != STREAM_RESET_RESPONSE_PARAMETER) {
                    break;
                }
                auto *liveresparam = check_and_cast<const SctpStreamResetResponseParameter *>(liveParameter);
                if (!(storedresparam->getSrResSn() == liveresparam->getSrResSn())) {
                    return false;
                }
                if (!(flags & FLAG_RECONFIG_RESULT_NOCHECK))
                    if (!(storedresparam->getResult() == liveresparam->getResult()))
                        return false;
                if (storedresparam->getSendersNextTsn() != 0 && storedresparam->getResult() == PERFORMED) {
                    if (!(flags & FLAG_RECONFIG_SENDER_NEXT_TSN_NOCHECK))
                        if (!(storedresparam->getSendersNextTsn() + localDiffTsn == liveresparam->getSendersNextTsn()))
                            return false;
                    if (!(flags & FLAG_RECONFIG_RECEIVER_NEXT_TSN_NOCHECK))
                        if (!(storedresparam->getReceiversNextTsn() == liveresparam->getReceiversNextTsn()))
                            return false;
                }
                break;
            }
            case SSN_TSN_RESET_REQUEST_PARAMETER: {
                found = false;
                auto *storedinparam = check_and_cast<const SctpSsnTsnResetRequestParameter *>(storedParameter);
                for (unsigned int j = 0; j < liveReconfigChunk->getParametersArraySize(); j++) {
                    liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(j));
                    if (liveParameter->getParameterType() != SSN_TSN_RESET_REQUEST_PARAMETER)
                        continue;
                    else {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
                auto *liveinparam = check_and_cast<const SctpSsnTsnResetRequestParameter *>(liveParameter);
                if (seqNumMap[storedinparam->getSrReqSn()] == 0) {
                    seqNumMap[storedinparam->getSrReqSn()] = liveinparam->getSrReqSn();
                }
                else if (!(seqNumMap[storedinparam->getSrReqSn()] == liveinparam->getSrReqSn())) {
                    return false;
                }
                break;
            }
            case ADD_INCOMING_STREAMS_REQUEST_PARAMETER: {
                found = false;
                auto *storedaddparam = check_and_cast<const SctpAddStreamsRequestParameter *>(storedParameter);
                for (unsigned int j = 0; j < liveReconfigChunk->getParametersArraySize(); j++) {
                    liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(j));
                    if (liveParameter->getParameterType() != ADD_INCOMING_STREAMS_REQUEST_PARAMETER)
                        continue;
                    else {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
                auto *liveaddparam = check_and_cast<const SctpAddStreamsRequestParameter *>(liveParameter);
                if (seqNumMap[storedaddparam->getSrReqSn()] == 0) {
                    seqNumMap[storedaddparam->getSrReqSn()] = liveaddparam->getSrReqSn();
                }
                else if (!(seqNumMap[storedaddparam->getSrReqSn()] == liveaddparam->getSrReqSn())) {
                    return false;
                }
                if (!(storedaddparam->getNumberOfStreams() == liveaddparam->getNumberOfStreams()))
                    return false;
                break;
            }
            case ADD_OUTGOING_STREAMS_REQUEST_PARAMETER: {
                found = false;
                auto *storedaddparam = check_and_cast<const SctpAddStreamsRequestParameter *>(storedParameter);
                for (unsigned int j = 0; j < liveReconfigChunk->getParametersArraySize(); j++) {
                    liveParameter = check_and_cast<const SctpParameter *>(liveReconfigChunk->getParameters(j));
                    if (liveParameter->getParameterType() != ADD_OUTGOING_STREAMS_REQUEST_PARAMETER)
                        continue;
                    else {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
                auto *liveaddparam = check_and_cast<const SctpAddStreamsRequestParameter *>(liveParameter);
                if (seqNumMap[storedaddparam->getSrReqSn()] == 0) {
                    seqNumMap[storedaddparam->getSrReqSn()] = liveaddparam->getSrReqSn();
                }
                else if (!(seqNumMap[storedaddparam->getSrReqSn()] == liveaddparam->getSrReqSn())) {
                    return false;
                }
                if (!(storedaddparam->getNumberOfStreams() == liveaddparam->getNumberOfStreams()))
                    return false;
                break;
            }
            default:
                printf("Reconfig Parameter %d not implemented\n", storedParameter->getParameterType());
                break;
        }
    }
    return true;
}

bool PacketDrillApp::compareSackPacket(const SctpSackChunk *storedSackChunk, const SctpSackChunk *liveSackChunk)
{
    uint32_t flags = storedSackChunk->getFlags();
    if (!(flags & FLAG_SACK_CHUNK_CUM_TSN_NOCHECK))
        if (!(storedSackChunk->getCumTsnAck() == liveSackChunk->getCumTsnAck()))
            return false;

    peerCumTsn = liveSackChunk->getCumTsnAck();
    if (!(flags & FLAG_SACK_CHUNK_A_RWND_NOCHECK))
        if (!(storedSackChunk->getA_rwnd() == liveSackChunk->getA_rwnd()))
            return false;

    if (!(flags & FLAG_SACK_CHUNK_GAP_BLOCKS_NOCHECK))
        if (!(storedSackChunk->getNumGaps() == liveSackChunk->getNumGaps()))
            return false;

    if (storedSackChunk->getNumGaps() > 0) {
        for (int i = 0; i < storedSackChunk->getNumGaps(); i++) {
            if (!(storedSackChunk->getGapStart(i) == (liveSackChunk->getGapStart(i) - peerCumTsn))
                || !(storedSackChunk->getGapStop(i) == (liveSackChunk->getGapStop(i) - peerCumTsn)))
            {
                return false;
            }
        }
    }

    if (!(flags & FLAG_SACK_CHUNK_DUP_TSNS_NOCHECK))
        if (!(storedSackChunk->getNumDupTsns() == liveSackChunk->getNumDupTsns()))
            return false;

    if (storedSackChunk->getNumDupTsns() > 0) {
        for (int i = 0; i < storedSackChunk->getNumDupTsns(); i++) {
            if (!(storedSackChunk->getDupTsns(i) == liveSackChunk->getDupTsns(i))) {
                return false;
            }
        }
    }

    return true;
}

void PacketDrillApp::handleStartOperation(LifecycleOperation *operation)
{
    if (operation != nullptr)
        throw cRuntimeError("Lifecycle currently not implemented");
}

void PacketDrillApp::handleStopOperation(LifecycleOperation *operation)
{
    throw cRuntimeError("Lifecycle currently not implemented");
}

void PacketDrillApp::handleCrashOperation(LifecycleOperation *operation)
{
    throw cRuntimeError("Lifecycle currently not implemented");
}

} // namespace INET

