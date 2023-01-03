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

#include <stdlib.h>
#include "inetgpl/queueing/scheduler/HlsScheduler.h"
#include <string.h>

namespace inetgpl {
namespace queueing {

Define_Module(HlsScheduler);

// initialize the scheduler
void HlsScheduler::initialize(int stage)
{
    PacketSchedulerBase::initialize(stage); // Initialize the packet scheduler module
    if (stage == INITSTAGE_LOCAL) {
        mtu = par("mtu");
        getParentModule()->subscribe(packetPushEndedSignal, this);
        EV_INFO << "HlsScheduler: parent = " << getParentModule()->getFullPath() << endl;

        dequeueIndexSignal = registerSignal("dequeueIndex");
        roundSizeSignal = registerSignal("roundSize");
        phyHeaderSize = par("phyLayerHeaderLength");

        // Get all leaf queues.
        for (auto provider : providers) {
            collections.push_back(dynamic_cast<IPacketCollection *>(provider)); // Get pointers to queues
        }

        // push -1 at the linked list, -1 presents the end of the round robin, i.e. after the round robin reaches -1 a new round should start
        roundRobin.push_front(-1);
        currentPointer = roundRobin.begin();

        // Load config
        hlsConfig = par("hlsTreeConfig");

        createAllClasses(hlsConfig);

        //printAllClasses();

    }
}

// Gets all classes info from the XML, creates classes and the tree structure
void HlsScheduler::createAllClasses(cXMLElement *hlsConfig)
{
    cXMLElementList classes = hlsConfig->getChildren();
    for (auto &node : classes) {
        hlsClass* newClass = new hlsClass();
        // set a class id for the new class
        newClass->classId = numClasses++;
        // set mtu to default mtu (only matters if class is leaf)
        newClass->leafMtu = mtu;
        // push class pointer to vector of all classes
        allClasses.push_back(newClass);
        // set the name and add the name and the class id to the map
        newClass->name = node->getAttribute("id");
        std::string nameString(newClass->name);
        nameToId[nameString] = newClass->classId;
        // set the weight of the class, it does not need a weight if it is the root, but can have one (modifies total balance in tree)
        cXMLElement *weight = node->getFirstChildWithTag("weight");
        if(weight != nullptr) {
            newClass->weight = atoi(weight->getNodeValue());
        }
        // if defined on XML get mtu specific to the leaf
        cXMLElement *leafMtu = node->getFirstChildWithTag("mtu");
        if(leafMtu != nullptr) {
            newClass->leafMtu = atoi(leafMtu->getNodeValue());
        }
        // try to get queueId if it exists, i.e. the class is a leaf, it will get ignored if the class is not a leaf even if queueId exists on XML
        cXMLElement *queueId = node->getFirstChildWithTag("queueId");
        if(queueId != nullptr) {
            newClass->queueId = atoi(queueId->getNodeValue());
        }
    }
    // set parents using allClasses vector and nameToId map
    for (auto &node : classes) {
        // get hlsClass of the current XML class
        std::string name(node->getAttribute("id"));
        hlsClass *currentClass = allClasses[nameToId[name]];
        // get the parent id and find the corresponding hlsClass
        std::string parentName(node->getFirstChildWithTag("parentId")->getNodeValue());
        if(nameToId.find(parentName) == nameToId.end()) {
            // if parentName is NULL the current class is the root
            if(parentName == "NULL") {
                if(root != nullptr) {
                    throw cRuntimeError("There are multiple roots");
                }
                root = currentClass;
            }
            else {
                // the parent id does not exist, throw an error
                throw cRuntimeError("Id of the parent of the class %s is not found! Set the parent id to \"NULL\" if the class is the root", node->getAttribute("id"));
            }
        }
        else {
            currentClass->parent = allClasses[nameToId[parentName]];
            currentClass->parent->numChildren++;
        }
    }
    // throw an error if no root is found
    if(root == nullptr) {
        throw cRuntimeError("There is no root, set the parent id to \"NULL\" if the class is the root");
    }
    int numLeafs = 0;
    //find the number of leaves to fill queueIdToLeafClass vector
    for(int i = 0; i < numClasses; ++i) {
        hlsClass *cl = allClasses[i];
        // add weights of every class to root quota
        root->quota += cl->weight;
        roundSize += cl->weight;
        // if the number of children is equal to 0 it is a leaf
        if(allClasses[i]->numChildren == 0) {
            ++numLeafs;

            // register signals
            char totalSignalName[50];
            sprintf(totalSignalName, "class-%s-totalQuota", cl->name);
            cl->totalQuota = registerSignal(totalSignalName);

            char totalStatisticName[50];
            sprintf(totalStatisticName, "class-%s-totalQuota", cl->name);
            cProperty *statisticTemplate = getProperties()->get("statisticTemplate", "totalQuota");
            getEnvir()->addResultRecorders(this, cl->totalQuota, totalStatisticName, statisticTemplate);

            char addedSignalName[50];
            sprintf(addedSignalName, "class-%s-addedQuota", cl->name);
            cl->addedQuota = registerSignal(addedSignalName);

            char addedStatisticName[50];
            sprintf(addedStatisticName, "class-%s-addedQuota", cl->name);
            statisticTemplate = getProperties()->get("statisticTemplate", "addedQuota");
            getEnvir()->addResultRecorders(this, cl->addedQuota, addedStatisticName, statisticTemplate);

            // if xml did not have queue id throw error
            if(allClasses[i]->queueId == -1) {
                throw cRuntimeError("The leaf %s does not have a queue id", allClasses[i]->name);
            }
        }
    }
    queueIdToLeafClasses.resize(numLeafs, nullptr);
    // add leaf classes to queueIdToLeafClass
    for(int i = 0; i < numClasses; ++i) {
        // if the number of children is equal to 0 it is a leaf
        if(allClasses[i]->numChildren == 0) {
            queueIdToLeafClasses[allClasses[i]->queueId] = allClasses[i];
        }
    }

}

/*
 * METHODS FOR OMNET++ EVENTS - BEGIN
 */

// Wrapper for scheduleAt method
void HlsScheduler::scheduleAt(simtime_t t, cMessage *msg)
{
    Enter_Method("scheduleAt");
    cSimpleModule::scheduleAt(t, msg);
}

// Wrapper for cancelEvent method
cMessage *HlsScheduler::cancelEvent(cMessage *msg)
{
    Enter_Method("cancelEvent");
    return cSimpleModule::cancelEvent(msg);
}

// Handle internal events
void HlsScheduler::handleMessage(cMessage *message)
{
    Enter_Method("handleMessage");
    throw cRuntimeError("Unknown self message");
}

/*
 * METHODS FOR OMNET++ EVENTS - END
 */

// computes the fair share of a class according to HLS algorithm
void HlsScheduler::hlsComputeFairShare(hlsClass *cl)
{
    // if there is negative quota(can only happen at root), set quota to 0
    if(cl->quota <= 0) {
        cl->fairShare = 0;
    }
    else {
        if(cl->busyChildrenWeight != 0) {
            cl->fairShare = cl->quota / cl->busyChildrenWeight;
        }
        else {
            // throw an error if we enter this function while the class is idle
            throw cRuntimeError("Trying to compute fair share when the class is idle");
        }
    }
}

// take quota from parent and update fair share
void HlsScheduler::hlsUpdateQuota(hlsClass *cl)
{
    // check if we already updated in the current round
    if(cl->lastUpdatedRound == currentRound) {
        return;
    }

    long long takenQuota = 0;

    if(cl->parent != nullptr) {
        hlsUpdateQuota(cl->parent);
        // take the quota from parent
        takenQuota = cl->weight * cl->parent->fairShare;
        cl->quota += takenQuota;
        cl->parent->quota -= takenQuota;
    }

    //EV << "--------Round: " << currentRound << " name: " << cl->name << " q: " << takenQuota << " total: " << cl->quota << endl;
    /*if(cl->parent != nullptr) {
        EV << "--------Parent share: " << cl->parent->fairShare << " weight: " << cl->weight << endl;
    }*/

    cl->lastUpdatedRound = currentRound;
    // compute fair share for our children as now we taken our fair share from our parent if cl is not leaf
    if(cl->numChildren > 0) {
        hlsComputeFairShare(cl);
    }
    else {
        emit(cl->totalQuota, cl->quota);
        emit(cl->addedQuota, takenQuota);
    }
}

// helper function to go next in linked list
void HlsScheduler::hlsListGoNext(std::list<int>::iterator &it) {
    ++it;
    // if the pointer is at the tail return to the head
    if(it == roundRobin.end()) {
        it = roundRobin.begin();
    }
}

// helper function to go back in linked list
void HlsScheduler::hlsListGoBack(std::list<int>::iterator &it) {
    // if the pointer is at the head go to the tail
    if(it == roundRobin.begin()) {
        it = --roundRobin.end();
    }
    else {
        --it;
    }
}

// advance the round robin
void HlsScheduler::hlsAdvanceRoundRobin()
{
    // if the queue is empty(except round marker) return
    if(roundRobin.size() == 1) {
        return;
    }
    // advance the pointer
    hlsListGoNext(currentPointer);

    // if current value is -1 that means we reached the end and need to start a new round
    if(*currentPointer == -1) {
        ++currentRound;
        emit(roundSizeSignal, roundSize);

        /*long long checkRoundSize = 0;
        for(int i = 0; i < numClasses; ++i) {
            checkRoundSize += allClasses[i]->quota;
        }
        EV << "------------- Check round size: " << roundSize << " " << checkRoundSize << endl;
        if(roundSize != checkRoundSize) {
            throw cRuntimeError("roundSize is wrong");
        }*/

        // take care if next entry is going to be deleted now (hlsAdvanceRoundRobin called from hlsSetIdle())
        auto tempIterator = currentPointer;
        hlsListGoNext(tempIterator);
        if(allClasses[*tempIterator]->isBusy == false) {
            return;
        }
        hlsAdvanceRoundRobin();
    }
    // else update the leaf that is next in round robin
    else {
        hlsClass *cl = allClasses[*currentPointer];
        // update leaf
        hlsUpdateQuota(cl);
    }
}

// if a class became busy add its weight to the parents busyChildenWeight, if class is leaf add to round robin
void HlsScheduler::hlsSetBusy(hlsClass *cl)
{
    // if busy children weight is bigger than 0 the class is already busy (if its an inner class)
    // update quota first so that if its children changes its busyChildrenWeight it does not affect the current round
    if(cl->isBusy == true) {
        hlsUpdateQuota(cl);
        return;
    }

    // set class as busy
    cl->isBusy = true;
    ++numBusyClasses;

    // if the class was not busy we will recursively set its parent also as busy, till we find an ancestor that is already busy
    if(cl->parent != nullptr) {
        hlsSetBusy(cl->parent);
        cl->parent->busyChildrenWeight += cl->weight;
    }

    // set lastUpdatedRound to current round so that it does not update during current round
    cl->lastUpdatedRound = currentRound;

    // if the class is a leaf add it to round robin and add mtu to root quota
    if(cl->numChildren == 0) {
        // add id of the class to the back of the currentPointer
        roundRobin.insert(currentPointer, cl->classId);
        // set pointer
        cl->locationInList = --currentPointer;
        ++currentPointer;
        root->quota += cl->leafMtu;
        roundSize += cl->leafMtu;
    }
}

// if a class became idle subtract its weight from the parents busyChildenWeight, if class is leaf remove it from round robin
void HlsScheduler::hlsSetIdle(hlsClass *cl)
{
    if(cl->parent != nullptr) {
        // donate quota to parent
        cl->parent->quota += cl->quota;
        cl->quota = 0;
        // remove busy child from parent
        cl->parent->busyChildrenWeight -= cl->weight;
        // if parent also becomes idle recursively call hlsSetIdle
        if(cl->parent->busyChildrenWeight == 0) {
            hlsSetIdle(cl->parent);
        }
    }

    cl->fairShare = 0;
    cl->isBusy = false;
    --numBusyClasses;

    //if class is a leaf remove it from round robin
    if(cl->numChildren == 0) {

        // remove mtu from root quota
        root->quota -= cl->leafMtu;

        roundSize -= cl->leafMtu;

        //if round robin is at this leaf advance round robin, then delete
        if(*currentPointer == cl->classId) {
            hlsAdvanceRoundRobin();
        }

        roundRobin.erase(cl->locationInList);

    }

}

void HlsScheduler::handleCanPullPacketChanged(cGate *gate)
{
    Enter_Method("handleCanPullPacketChanged");
    if(canPullSomePacket(gate)) {
        PacketSchedulerBase::handleCanPullPacketChanged(gate);
    }
}

// Returns the number of packets available to dequeue.
int HlsScheduler::getNumPackets() const
{
    int numPackets = 0; // Number of packets available for dequeueing
    for (auto collection : collections) {
        numPackets += collection->getNumPackets();
    }
    return numPackets;
}

bool HlsScheduler::canPullSomePacket(cGate *gate) const
{
    return numBusyClasses > 0;
}

b HlsScheduler::getTotalLength() const
{
    b totalLength(0);
    for (auto collection : collections)
        totalLength += collection->getTotalLength();
    return totalLength;
}

Packet *HlsScheduler::getPacket(int index) const
{
    int origIndex = index;
    for (auto collection : collections) {
        auto numPackets = collection->getNumPackets();
        if (index < numPackets)
            return collection->getPacket(index);
        else
            index -= numPackets;
    }
    throw cRuntimeError("Index %i out of range", origIndex);
}

void HlsScheduler::removePacket(Packet *packet)
{
    Enter_Method("removePacket");
    for (auto collection : collections) {
        int numPackets = collection->getNumPackets();
        for (int j = 0; j < numPackets; j++) {
            if (collection->getPacket(j) == packet) {
                collection->removePacket(packet);
                return;
            }
        }
    }
    throw cRuntimeError("Cannot find packet");
}

void HlsScheduler::removeAllPackets()
{
    Enter_Method("removeAllPacket");
    for (auto collection : collections)
        collection->removeAllPackets();
}

void HlsScheduler::receiveSignal(cComponent *source, simsignal_t signal, cObject *object, cObject *details)
{
    Enter_Method("%s", cComponent::getSignalName(signal));
    if (signal == packetPushEndedSignal) {
        if (std::string(source->getClassName()).find("inet::queueing::PacketQueue") != std::string::npos) { // Might need adjustment so that we can use compound packet queues as queues
            int index = static_cast<cModule*>(source)->getIndex();
            //EV_INFO << "HlsScheduler::receiveSignal: PacketQueue " << index << " emitted a packetPushed signal! Call hlsEnqueue for leaf with queueId " << index << endl;
            hlsEnqueue(index);
        }
    }
    else
        throw cRuntimeError("Unknown signal");
}

// after getting the signal that a packet was added to queue, if the corresponding leaf is idle it will get set to busy
void HlsScheduler::hlsEnqueue(int index)
{
    hlsClass *cl = queueIdToLeafClasses[index];
    // if leaf is not busy set it as busy
    if(cl->isBusy == false) {
        hlsSetBusy(cl);
    }
    handleCanPullPacketChanged(outputGate);
}

// choose which queue to dequeue the packet from
int HlsScheduler::hlsDequeue()
{
    hlsClass *cl;

    while(1) {
        // if pointer shows round marker advance round robin, should only happen at the very start
        if(*currentPointer == -1) {
            hlsAdvanceRoundRobin();
        }

        // if round robin is empty except the round marker return -1
        if(roundRobin.size() == 1) {
            return -1;
        }

        cl = allClasses[*currentPointer];

        // if there is no packet set leaf to idle
        if(collections[cl->queueId]->isEmpty()) {
            hlsSetIdle(cl);
            continue;
        }

        Packet *packetToPop = providers[cl->queueId]->canPullPacket(inputGates[cl->queueId]);

        int packetLength = packetToPop->getByteLength() + phyHeaderSize;
        // if quota is enough to send, send the packet
        if(packetLength <= cl->quota) {
            cl->quota -= packetLength;
            root->quota += packetLength;
            // if this is the last packet set leaf to idle
            if(collections[cl->queueId]->getNumPackets() <= 1) {
                hlsSetIdle(cl);
            }
            return cl->queueId;
        }
        else {
            hlsAdvanceRoundRobin();
        }
    }

}

// send the index of the queue to be dequeued to the interface
int HlsScheduler::schedulePacket()
{
    int dequeueIndex = hlsDequeue();
    emit(dequeueIndexSignal, dequeueIndex);
    return dequeueIndex;
}

// print info of one class
void HlsScheduler::printClass(hlsClass *cl)
{
    EV << "-----Name: " <<  cl->name << endl;
    EV << "Weight: " << cl->weight << endl;
    EV << "numChildren: " << cl->numChildren << endl;
    EV << "busyChildrenWeight: " << cl->busyChildrenWeight << endl;
    EV << "queueId: " << cl->queueId << endl;
    if(cl->parent != nullptr) {
        EV << "parent name: " << cl->parent->name << endl;
    }
}

// print info of all classes
void HlsScheduler::printAllClasses() {
    for(auto i : allClasses) {
        printClass(i);
    }
}

}
}

