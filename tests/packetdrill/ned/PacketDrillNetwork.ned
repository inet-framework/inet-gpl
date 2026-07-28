//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// The network of the INET run: one PacketDrillHost, whose PacketDrillApp plays the
// peer of the script over a tun interface. The app simulates the peer itself, so
// the network needs no second host. The addresses are the same as in the Linux run
// (local 192.168.0.1, remote 192.0.2.1): ini/base.ini sets them, and pdhost.mrt
// gives the route.
//

import inetgpl.node.packetdrill.PacketDrillHost;

network PacketDrillNetwork
{
    parameters:
    submodules:
        pdhost: PacketDrillHost {
            parameters:
                ipv4.configurator.networkConfiguratorModule = "";
                @display("p=544,194;i=device/server_l");
        }
    connections:
}
