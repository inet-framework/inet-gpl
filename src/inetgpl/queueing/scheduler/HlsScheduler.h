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


#ifndef __INET_HlsScheduler_H
#define __INET_HlsScheduler_H

#include <string>
#include <set>
#include <vector>
#include <map>
#include <list>

#include "inet/common/XMLUtils.h"
#include "inet/queueing/base/PacketSchedulerBase.h"
#include "inet/queueing/contract/IPacketCollection.h"

namespace inetgpl {
namespace queueing {
using namespace inet;
using namespace inet::queueing;

class INET_API HlsScheduler : public PacketSchedulerBase, public IPacketCollection, public cListener
{
  protected:

    simsignal_t dequeueIndexSignal; // signal for queue index that was dequeued
    simsignal_t roundSizeSignal; // signal for round size

    std::vector<IPacketCollection *> collections; // The actual queues

    int mtu;
    int currentRound = 0; // the number of the current round
    int numClasses = 0; // number of classes
    int numBusyClasses = 0; // number of busy classes

    int phyHeaderSize = 8; // header size of used physical layer


    long long roundSize = 0; // total quota in the graph

    std::list<int> roundRobin; // Linked list for round robin of leaf classes, uses the classId
    std::list<int>::iterator currentPointer;
    // Structure for the class
    struct hlsClass {
        const char *name = "";
        long long quota = 0;  // Current balance of the node

        simsignal_t totalQuota; // signal for total quota of class
        simsignal_t addedQuota; // signal for added quota of class in the current round

        int numChildren = 0; // Number of connected children
        std::list<int>::iterator locationInList; // pointing to the location in roundRobin list
        int queueId = -1; // only used if the node is a leaf
        bool isBusy = 0; // shows if class is busy
        int leafMtu = 1500; // mtu specific to the leaf, if not defined in XML it will be the equal to HlsScheduler.mtu

        int lastUpdatedRound = 0; // round where the fair quota was last updated
        long long fairShare = 0; // fair quota as explained in HLS
        long long weight = 0; // the weight of the node, used in HLS
        long long busyChildrenWeight = 0; // sum of the weights of the busy children

        hlsClass *parent = nullptr; // Pointer to parent node. nullptr for root
        // We only need to know the parent, not the children as we only traverse up the tree in the algorithm.

        int classId; // Unique ID
    };



    cXMLElement *hlsConfig = nullptr; // XML config for the HLS tree

    hlsClass* root = nullptr; // Root class saved here
    std::vector<hlsClass*> allClasses; // All classes saved here for ease of access
    std::map<std::string, int> nameToId; // Maps classes names to id's
    std::vector<hlsClass*> queueIdToLeafClasses; // stores the leaf class given the queue id as index

    virtual void initialize(int stage) override;
    virtual int schedulePacket() override;
    virtual void handleMessage(cMessage *msg) override;

    void createAllClasses(cXMLElement *hlsConfig);
    void hlsComputeFairShare(hlsClass *cl);
    void hlsUpdateQuota(hlsClass *cl);
    void hlsAdvanceRoundRobin();
    void hlsSetBusy(hlsClass *cl);
    void hlsSetIdle(hlsClass *cl);
    void hlsListGoNext(std::list<int>::iterator &it);
    void hlsListGoBack(std::list<int>::iterator &it);
    void printClass(hlsClass *cl);
    void printAllClasses();

  public:

    int hlsDequeue();
    void hlsEnqueue(int index);

    virtual int getMaxNumPackets() const override { return -1; }
    virtual int getNumPackets() const override;
    virtual bool canPullSomePacket(cGate *gate) const override;

    virtual b getMaxTotalLength() const override { return b(-1); }
    virtual b getTotalLength() const override;

    virtual bool isEmpty() const override { return numBusyClasses == 0; }
    virtual Packet *getPacket(int index) const override;
    virtual void removePacket(Packet *packet) override;
    virtual void removeAllPackets() override;
    virtual void handleCanPullPacketChanged(cGate *gate) override;



    virtual void scheduleAt(simtime_t t, cMessage *msg) override;
    virtual cMessage *cancelEvent(cMessage *msg) override;

    virtual void receiveSignal(cComponent *source, simsignal_t signal, cObject *object, cObject *details) override;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_HlsScheduler_H

