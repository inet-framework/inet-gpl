//
// Copyright (C) 2009 Kristjan V. Jonsson, LDSS (kristjanvj@gmail.com)
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#ifndef __INETGPL_HTTPNODEBASE_H
#define __INETGPL_HTTPNODEBASE_H

#include <fstream>
#include <iostream>
#include <map>
#include <queue>
#include <string>

#include "inetgpl/applications/httptools/common/HttpMessages_m.h"
#include "inetgpl/applications/httptools/common/HttpRandom.h"
#include "inetgpl/applications/httptools/common/HttpUtils.h"
#include "inetgpl/applications/httptools/configurator/HttpController.h"
#include "inet/common/lifecycle/LifecycleUnsupported.h"
#include "inet/common/packet/Packet.h"

namespace inetgpl {

namespace httptools {

#define HTTPT_REQUEST_MESSAGE             10000
#define HTTPT_DELAYED_REQUEST_MESSAGE     10001
#define HTTPT_RESPONSE_MESSAGE            10010
#define HTTPT_DELAYED_RESPONSE_MESSAGE    10011

enum LogFormat { lf_short, lf_long };

/**
 * The base class for browser and server nodes.
 *
 * See the derived classes HttpBrowserBase and HttpServerBase for details
 *
 * @see HttpBrowserBase
 * @see HttpServerBase
 *
 * @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class INETGPL_API HttpNodeBase : public cSimpleModule, public LifecycleUnsupported
{
  protected:
    double linkSpeed = 0; // the link speed in bits per second. Only needed for direct message passing transmission delay calculations
    int httpProtocol = 0; // the http protocol. http/1.0: 10 ; http/1.1: 11
    std::string logFileName; // the log file name for message generation events
    bool enableLogging = true; // enable/disable of logging message generation events to file
    LogFormat outputFormat = lf_short; // The format used to log message events to the log file (if enabled)
    bool m_bDisplayMessage = true; // enable/disable logging of message events to the console
    bool m_bDisplayResponseContent = true; // enable/disable of logging message contents (body) to the console. Only if m_bDisplayMessage is set
    cModule *host = nullptr;

  protected:
    /* Direct message passing utilities */

    /*
     * Send a single message direct to the specified module.
     * Transmission delay is automatically calculated from the size of the message. In addition, a constant delay
     * a random delay object may be specified. Those delays add to the total used to submit the message to the
     * OMNeT++ direct message passing mechanism.
     */
    void sendDirectToModule(HttpNodeBase *receiver, Packet *packet, simtime_t constdelay = 0.0, rdObject *rd = nullptr);

    /*
     * Calculate the transmission delay for the packet
     */
    double transmissionDelay(Packet *packet);

    /*
     * Methods for logging and formatting messages
     */
    void logRequest(const Ptr<const HttpRequestMessage>& httpRequest);
    void logResponse(const Ptr<const HttpReplyMessage>& httpResponse);
    void logEntry(std::string line);
    std::string formatHttpRequestShort(const Ptr<const HttpRequestMessage>& httpRequest);
    std::string formatHttpRequestLong(const Ptr<const HttpRequestMessage>& httpRequest);
    std::string formatHttpResponseShort(const Ptr<const HttpReplyMessage>& httpResponse);
    std::string formatHttpResponseLong(const Ptr<const HttpReplyMessage>& httpResponse);

  public:
    HttpNodeBase();
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
};

} // namespace httptools

} // namespace inet

#endif

