//Hierarchical Link Sharing Implementation for OMNeT++ and INET Framework
//
//SPDX-License-Identifier: GPL-2.0-or-later
//
//Author: Atacan Iyidogan
//Advised by: Marcin Bosk, Filip Rezabek
//
//This implementation is based on:
//1. HTB Scheduler for INET framework (https://github.com/inet-framework/inet-gpl/blob/master/src/inetgpl/queueing/scheduler/HtbScheduler.cc and other relevant files)
//2. HLS Linux Qdisc implementation (https://github.com/lantua/HLS/blob/main/sch_hls.c)
//3. Publications:
//    - Luangsomboon, N., & Liebeherr, J. (2021). A Round-Robin Packet Scheduler for Hierarchical Max-Min Fairness. arXiv preprint arXiv:2108.09864.
//    - Luangsomboon, N., & Liebeherr, J. (2021, November). HLS: A Packet Scheduler for Hierarchical Fairness. In 2021 IEEE 29th International Conference on Network Protocols (ICNP) (pp. 1-11). IEEE.


package inetgpl.examples.hls;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;
import ned.DatarateChannel;

network hlsExperimentPaper
{
    parameters:
        @display("bgb=710,417");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=10,10;is=s");
        }

        trafficGenerator: StandardHost {
            @display("p=140,203");
        }
        
        scheduler: StandardHost {
        	@display("p=330,203");
        }

        trafficSink: StandardHost {
            @display("p=565,203");
        }

    connections:
        trafficGenerator.ethg++ <--> ethLink1: DatarateChannel <--> scheduler.ethg++;
        scheduler.ethg++ <--> ethLink2: DatarateChannel <--> trafficSink.ethg++;
}

