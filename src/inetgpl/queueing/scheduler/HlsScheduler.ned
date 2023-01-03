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


package inetgpl.queueing.scheduler;

import inet.queueing.base.PacketSchedulerBase;
import inet.queueing.contract.IPacketScheduler;

simple HlsScheduler extends PacketSchedulerBase like IPacketScheduler
{
    parameters:
        xml hlsTreeConfig; // The hls tree structure
        int mtu @unit(B) = default(1500B);
        int phyLayerHeaderLength @unit(B) = default(8B);

        @class(HlsScheduler);
        
        @signal[dequeueIndex](type=long);
        @statistic[dequeueIndex](title="Index of a queue that just dequeued"; record=vector);
        
        @signal[class-*-totalQuota](type=long);
        @statisticTemplate[totalQuota](record=vector);
        
        @signal[class-*-addedQuota](type=long);
        @statisticTemplate[addedQuota](record=vector, stats, sum);
        
        @signal[roundSize](type=long);
        @statistic[roundSize](source = "roundSize"; record = stats, histogram, vector);
}
