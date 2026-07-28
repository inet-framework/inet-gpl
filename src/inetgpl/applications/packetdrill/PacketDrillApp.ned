//
// Copyright (C) 2015 Irene Ruengeler
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

package inetgpl.applications.packetdrill;

import inet.applications.contract.IApp;

//
// This is a port of Google's Packetdrill testing tool into the INET Framework.
//
// Google released the script-based Packetdrill tool in 2013. It allows one
// to test transport protocols like UDP and TCP on Linux and BSD-based
// operating systems. Scripts define test cases that inject packets to the
// protocol implementation under test, perform operations using the API
// controlling the transport protocol, and verify the sending of packets, all
// at specified times. The ported version provides a simple and powerful
// method of testing transport protocols implemented in INET.
//
simple PacketDrillApp like IApp
{
    parameters:
        string scriptFile;
        double startTime @unit(s) = default(0s);
        int localPort; // port number of the initiator
        int remotePort;
        string localAddress;
        string remoteAddress;
        string interfaceTableModule;
        string interface;   // tun interface name
        int inboundStreams = default(20);
        int outboundStreams = default(20);
        int streamReset = default(0);
        string crcMode @enum("declared", "computed") = default("declared");
        double latency @unit(s) = default(0s);
        // Explicit-read receive model: TCP sockets run with autoRead=false and every
        // script read()/recv() issues a TCP READ request, so arrived-but-unread data
        // stays in TCP's receive queue exactly like unread data in a Linux socket
        // buffer -- receive-window shrink, buffer-occupancy acceptance decisions and
        // delayed-ACK gating then follow genuine occupancy. Off by default: most
        // corpus scripts read promptly and the autoRead model is equivalent for them.
        bool explicitRead = default(false);
        @display("i=block/app");
    gates:
        input socketIn;
        output socketOut;
}

