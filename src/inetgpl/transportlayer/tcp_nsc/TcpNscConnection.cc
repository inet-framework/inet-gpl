//
// Copyright (C) 2006 Sam Jansen, Andras Varga
// Copyright (C) 2009 OpenSim Ltd.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
//

#include <assert.h>
#include <dlfcn.h>
#include <netinet/in.h>

#include "inet/common/ProtocolTag_m.h"
#include "inet/common/checksum/TcpIpChecksum.h"
#include "inet/common/socket/SocketTag_m.h"
#include "inet/transportlayer/contract/tcp/TcpCommand_m.h"
#include "inet/transportlayer/tcp_common/TcpHeader.h"
#include "inet/transportlayer/tcp_common/headers/tcphdr.h"

#include "inetgpl/transportlayer/tcp_nsc/TcpNscConnection.h"
#include "inetgpl/transportlayer/tcp_nsc/queues/TcpNscQueues.h"
#include "inetgpl/transportlayer/tcp_nsc/TcpNsc.h"

#include <sim_interface.h> // NSC header

namespace inetgpl {

namespace tcp {

static const unsigned short PORT_UNDEF = -1;

struct nsc_iphdr
{
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif BYTE_ORDER == BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else // if BYTE_ORDER == LITTLE_ENDIAN
# error "Please check BYTE_ORDER declaration"
#endif // if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
} __attribute__((packed));

TcpNscConnection::TcpNscConnection()
    :
    connIdM(-1),
    pNscSocketM(nullptr),
    sentEstablishedM(false),
    onCloseM(false),
    disconnectCalledM(false),
    isListenerM(false),
    tcpWinSizeM(65536),
    tcpNscM(nullptr),
    receiveQueueM(nullptr),
    sendQueueM(nullptr)
{
}

TcpNscConnection::~TcpNscConnection()
{
    delete receiveQueueM;
    delete sendQueueM;
}

void TcpNscConnection::connect(INetStack& stackP, SockPair& inetSockPairP, SockPair& nscSockPairP)
{
    ASSERT(!pNscSocketM);
    pNscSocketM = stackP.new_tcp_socket();
    ASSERT(pNscSocketM);

    // TODO NSC not yet implements bind (for setting localport)

    ASSERT(sendQueueM);
    ASSERT(receiveQueueM);

    sendQueueM->setConnection(this);
    receiveQueueM->setConnection(this);

    onCloseM = false;

    pNscSocketM->connect(nscSockPairM.remoteM.ipAddrM.str().c_str(), nscSockPairM.remoteM.portM);

    struct sockaddr_in sockAddr;
    size_t sockAddrLen = sizeof(sockAddr);
    pNscSocketM->getsockname((sockaddr *)&sockAddr, &sockAddrLen);
    nscSockPairP.localM.ipAddrM.set(Ipv4Address(sockAddr.sin_addr.s_addr));
    nscSockPairP.localM.portM = ntohs(sockAddr.sin_port);
/*
    // TODO getpeername generate an assert!!!
    pNscSocketM->getpeername((sockaddr*)&sockAddr, &sockAddrLen);
    nscSockPairP.remoteM.ipAddrM.set(sockAddr.sin_addr.s_addr);
    nscSockPairP.remoteM.portM = ntohs(sockAddr.sin_port);
 */
}

void TcpNscConnection::listen(INetStack& stackP, SockPair& inetSockPairP, SockPair& nscSockPairP)
{
    ASSERT(nscSockPairP.localM.portM != PORT_UNDEF);
    ASSERT(!pNscSocketM);
    ASSERT(sendQueueM);
    ASSERT(receiveQueueM);

    isListenerM = true;
    pNscSocketM = stackP.new_tcp_socket();
    ASSERT(pNscSocketM);

    // TODO NSC not yet implements bind (for setting remote addr)

    sendQueueM->setConnection(this);
    receiveQueueM->setConnection(this);

    onCloseM = false;

    pNscSocketM->listen(nscSockPairP.localM.portM);

    struct sockaddr_in sockAddr;
    size_t sockAddrLen = sizeof(sockAddr);
    pNscSocketM->getsockname((sockaddr *)&sockAddr, &sockAddrLen);

    nscSockPairP.localM.ipAddrM.set(Ipv4Address(sockAddr.sin_addr.s_addr));
    nscSockPairP.localM.portM = ntohs(sockAddr.sin_port);
    nscSockPairP.remoteM.ipAddrM = L3Address();
    nscSockPairP.remoteM.portM = PORT_UNDEF;
}

void TcpNscConnection::send(Packet *msgP)
{
    ASSERT(sendQueueM);
    sendQueueM->enqueueAppData(msgP);
}

void TcpNscConnection::do_SEND()
{
    if (pNscSocketM) {
        ASSERT(sendQueueM);

        char buffer[4096];
        int allsent = 0;

        while (1) {
            int bytes = sendQueueM->getBytesForTcpLayer(buffer, sizeof(buffer));

            if (0 == bytes)
                break;

            int sent = pNscSocketM->send_data(buffer, bytes);

            if (sent > 0) {
                sendQueueM->dequeueTcpLayerMsg(sent);
                allsent += sent;
            }
            else {
                EV_WARN << "TcpNsc connection: " << connIdM << ": Error do sending, err is " << sent << "\n";
                break;
            }
        }

        EV_DEBUG << "do_SEND(): " << connIdM << " sent:" << allsent << ", unsent:" << sendQueueM->getBytesAvailable() << "\n";

        if (onCloseM && sendQueueM->getBytesAvailable() == 0 && !disconnectCalledM) {
            disconnectCalledM = true;
            pNscSocketM->disconnect();
            auto indication = new Indication("CLOSED", TCP_I_CLOSED);
            TcpCommand *ind = new TcpCommand();
            indication->setControlInfo(ind);
            indication->addTag<PacketProtocolTag>()->setProtocol(&Protocol::tcp);
            indication->addTag<SocketInd>()->setSocketId(connIdM);
            tcpNscM->send(indication, "appOut");
            // FIXME this connection never will be deleted, stayed in tcpNscM. Should delete later!
        }
    }
}

void TcpNscConnection::close()
{
    onCloseM = true;
}

void TcpNscConnection::abort()
{
    sendQueueM->dequeueTcpLayerMsg(sendQueueM->getBytesAvailable());
    close();
}

} // namespace tcp

} // namespace inet

