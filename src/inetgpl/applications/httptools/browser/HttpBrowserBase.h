//
// Copyright (C) 2009 Kristjan V. Jonsson, LDSS (kristjanvj@gmail.com)
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#ifndef __INETGPL_HTTPBROWSERBASE_H
#define __INETGPL_HTTPBROWSERBASE_H

#include "inetgpl/applications/httptools/common/HttpNodeBase.h"
#include "inet/common/ModuleRefByPar.h"
#include "inet/common/packet/Packet.h"

namespace inetgpl {

namespace httptools {

#define MSGKIND_START_SESSION     0
#define MSGKIND_NEXT_MESSAGE      1
#define MSGKIND_SCRIPT_EVENT      2
#define MSGKIND_ACTIVITY_START    3

#define MAX_URL_LENGTH            2048 // The maximum allowed URL string length.

/**
 * A simulated browser module for OMNeT++ simulations. A part of HttpTools.
 *
 * The component is designed to plug into the existing INET StandardHost module as a
 * tcpApp. See the INET documentation and examples for details. It can also be used
 * with the simplified HttpDirectHost, which only supports direct message passing.
 *
 * The browser can operate in two modes:
 * - Random request mode: The browser uses the parameters supplied and statistical distributions
 *   to make requests.
 * - Scripted mode: The browser operates using a script file -- requests are issued to specific
 *   URLs and at specific times.
 *
 * The browser can operate in two communications modes:
 * - Direct mode, in which messages are passed directly using sendDirect. This removes topology
 *   variables from the simulation and simplifies setup considerably. This mode should be used
 *   whenever the topology of the network and the resulting effects are not of interest. This is
 *   implemented in the derived HttpBrowserDirect class.
 * - Socket mode, in which the INET TcpSocket is used to handle messages sent and received.
 *   This mode uses the full INET TCP/IP simulation. Requires the network topology to be set
 *   up -- routers, links, etc. This is implemented in the derived HttpBrowser class.
 *
 * @see HttpBrowser
 * @see HttpBrowserDirect
 *
 * @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class INETGPL_API HttpBrowserBase : public HttpNodeBase
{
  protected:
    /*
     * Browse event item. Used in scripted mode.
     */
    struct BrowseEvent {
        simtime_t time; // Event triggering time
        std::string wwwhost; // Host to contact
        std::string resourceName; // The resource to request
        HttpNodeBase *serverModule = nullptr; // Reference to the omnet server object. Resolved at parse time.
    };

    /*
     * Browse events queue. Used in scripted mode.
     */
    typedef std::deque<BrowseEvent> BrowseEventsList;

    /*
     * A list of HTTP requests to send.
     */
    typedef std::deque<Packet *> HttpRequestQueue;

    cMessage *eventTimer = nullptr; // The timer object used to trigger browsing events
    ModuleRefByPar<HttpController> controller; // Reference to the central controller object

    bool scriptedMode = false; // Set to true if a script file is defined
    BrowseEventsList browseEvents; // Queue of browse events used in scripted mode

    /* The current session parameters */
    int reqInCurSession = 0; // The number of requests made so far in the current session
    int reqNoInCurSession = 0; // The total number of requests to be made in the current session
    simtime_t acitivityPeriodEnd; // The end in simulation time of the current activity period

    /* The random objects */
    rdObject *rdProcessingDelay = nullptr;
    rdObject *rdActivityLength = nullptr;
    rdObject *rdInterRequestInterval = nullptr;
    rdObject *rdInterSessionInterval = nullptr;
    rdObject *rdRequestSize = nullptr;
    rdObject *rdReqInSession = nullptr;

    long htmlRequested = 0;
    long htmlReceived = 0;
    long htmlErrorsReceived = 0;
    long imgResourcesRequested = 0;
    long imgResourcesReceived = 0;
    long textResourcesRequested = 0;
    long textResourcesReceived = 0;
    long messagesInCurrentSession = 0;
    long sessionCount = 0;
    long connectionsCount = 0;

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void finish() override;
    virtual void handleMessage(cMessage *msg) override = 0;
    void handleDataMessage(Ptr<const HttpReplyMessage> msg);
    void handleSelfMessages(cMessage *msg);
    void handleSelfActivityStart();
    void handleSelfStartSession();
    void handleSelfNextMessage();
    void handleSelfScriptedEvent();
    void handleSelfDelayedRequestMessage(cMessage *msg);
    void scheduleNextBrowseEvent();

    /*
     * Pure virtual methods to communicate with the server. Must be implemented in derived classes
     */
    virtual void sendRequestToServer(BrowseEvent be) = 0;
    virtual void sendRequestToServer(Packet *request) = 0;
    virtual void sendRequestToRandomServer() = 0;
    virtual void sendRequestsToServer(std::string www, HttpRequestQueue queue) = 0;

    /*
     * Methods for generating HTML page requests and resource requests
     */
    Packet *generatePageRequest(std::string www, std::string page, bool bad = false, int size = 0);
    Packet *generateRandomPageRequest(std::string www, bool bad = false, int size = 0);
    Packet *generateResourceRequest(std::string www, std::string resource = "", int serial = 0, bool bad = false, int size = 0);

    /*
     * Read scripted events from file. Triggered if the script file parameter is specified in the initialization file.
     */
    void readScriptedEvents(const char *filename);

  public:
    HttpBrowserBase();
    virtual ~HttpBrowserBase();
};

} // namespace httptools

} // namespace inet

#endif

