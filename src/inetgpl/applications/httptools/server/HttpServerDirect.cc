//
// Copyright (C) 2009 Kristjan V. Jonsson, LDSS (kristjanvj@gmail.com)
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#include "inetgpl/applications/httptools/server/HttpServerDirect.h"

#include "inet/common/ModuleAccess.h"

namespace inetgpl {

namespace httptools {

Define_Module(HttpServerDirect);

void HttpServerDirect::initialize(int stage)
{
    HttpServerBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        EV_DEBUG << "Initializing direct server component\n";

        // Set the link speed
        linkSpeed = par("linkSpeed");
    }
}

void HttpServerDirect::finish()
{
    HttpServerBase::finish();
}

void HttpServerDirect::handleMessage(cMessage *msg)
{
    EV_DEBUG << "Handling received message " << msg->getName() << endl;
    if (msg->isSelfMessage()) {
        // Self messages are not used at the present
    }
    else {
        HttpNodeBase *senderModule = dynamic_cast<HttpNodeBase *>(msg->getSenderModule());
        if (senderModule == nullptr) {
            EV_ERROR << "Unspecified sender module in received message " << msg->getName() << endl;
            delete msg;
            return;
        }
        cModule *senderHost = getContainingNode(senderModule);
        EV_DEBUG << "Sender is " << senderModule->getFullName()
                 << " in host " << senderHost->getFullName() << endl;
        Packet *reply = handleReceivedMessage(check_and_cast<Packet *>(msg));
        // Echo back to the requester
        if (reply != nullptr)
            sendDirectToModule(senderModule, reply, 0.0, rdReplyDelay);
        delete msg;
    }
}

} // namespace httptools

} // namespace inet

