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


package inetgpl.queueing.queue;

import inet.queueing.contract.IPacketClassifier;
import inet.queueing.contract.IPacketQueue;
import inet.queueing.contract.IPacketScheduler;
import inet.queueing.queue.CompoundPacketQueueBase;


module HlsQueue extends CompoundPacketQueueBase
{
    parameters:
        int numQueues;
        xml hlsTreeConfig = default(xml("<config></config>")); // The hls tree structure
    submodules:
        classifier: <default("ContentBasedClassifier")> like IPacketClassifier {
            parameters:
                @display("p=100,100");
        }
        queue[numQueues]: <default("PacketQueue")> like IPacketQueue {
            parameters:
                bufferModule = default(exists(buffer) ? "^.buffer" : "");
                @display("p=325,100,column,125");
        }
        scheduler: <default("HlsScheduler")> like IPacketScheduler {
            parameters:
                hlsTreeConfig = default(parent.hlsTreeConfig);
                @display("p=550,100");
        }
    connections:
        in --> { @display("m=w"); } --> classifier.in;
        for i=0..sizeof(queue)-1 {
            classifier.out++ --> queue[i].in;
            queue[i].out --> scheduler.in++;
        }
        scheduler.out --> { @display("m=e"); } --> out;
}
