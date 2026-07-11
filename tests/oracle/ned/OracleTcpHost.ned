//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Single-host network for the TCP oracle test framework's leg-I runs: one
// PacketDrillApp-driven tun host, matching the addressing used on leg L
// (oracle.py's IPV4_FLAGS: local 192.168.0.1, remote 192.0.2.1... adjusted
// here to the legacy packetdrill-test peer address since PacketDrillApp
// simulates the peer directly, it does not need a routable "remote").
//

import inetgpl.node.packetdrill.PacketDrillHost;

network OracleTcpHost
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
