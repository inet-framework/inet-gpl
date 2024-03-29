// ----------------------------------------------------------------------------
//
// HttpTools Project
//
// This file is a part of the HttpTools project. The project was created at
// Reykjavik University, the Laboratory for Dependable Secure Systems (LDSS).
// Its purpose is to create a set of OMNeT++ components to simulate browsing
// behaviour in a high-fidelity manner along with a highly configurable
// Web server component.
//
// Maintainer: Kristjan V. Jonsson (LDSS) kristjanvj@gmail.com
// Project home page: code.google.com/p/omnet-httptools
//
// ----------------------------------------------------------------------------
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ----------------------------------------------------------------------------


package inetgpl.examples.httptools.socket.simpleddos;

import inetgpl.applications.httptools.configurator.HttpController;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;


//
// n-nodes test scenario for sockets.
//
// The scenario consists of a number of clients and servers connected to two routers. The routers are connected
// with a single link.
//
network HttpNnodes
{
    parameters:
        int numclients @prompt("Number of clients") = default(10);
    types:
        channel ethernetline extends ned.DatarateChannel
        {
            delay = 0.1us;
            datarate = 100Mbps;
        }
    submodules:
        //        channelInstaller: ChannelInstaller {
        //            parameters:
        ////                channelClass = "ThruputMeteringChannel";
        ////                channelAttrs = "format=u";
        //                @display("p=98,50;i=block/cogwheel_s");
        //        }
        configurator: Ipv4NetworkConfigurator {
            parameters:
                //                moduleTypes = "Router StandardHost";
                //                nonIPModuleTypes = "";
                config = xml("<config><interface hosts='*' address='145.236.x.x' netmask='255.255.x.x'/></config>");
                @display("is=s;p=100,100;i=block/cogwheel");
        }
        httpController: HttpController {
            parameters:
                @display("is=s;p=100,200;i=block/cogwheel");
        }
        router_c: Router {
            parameters:
                @display("p=400,200;i=abstract/router");
        }
        router_s: Router {
            parameters:
                @display("p=750,200;i=abstract/router");
        }
        client[numclients]: StandardHost {
            parameters:
                @display("i=device/laptop;p=250,100,ri,150,100");
        }
        thegood: StandardHost {
            parameters:
                @display("i=device/server;p=850,100");
        }
        thebad: StandardHost {
            parameters:
                @display("i=device/server;p=850,300");
        }
        theugly: StandardHost {
            parameters:
                @display("i=device/server;p=900,200");
        }
    connections allowunconnected:
        thegood.ethg++ <--> ethernetline <--> router_s.ethg++;
        thebad.ethg++ <--> ethernetline <--> router_s.ethg++;
        theugly.ethg++ <--> ethernetline <--> router_s.ethg++;
        for i=0..numclients-1 {
            client[i].ethg++ <--> ethernetline <--> router_c.ethg++;
        }
        router_s.ethg++ <--> ethernetline <--> router_c.ethg++;
}

