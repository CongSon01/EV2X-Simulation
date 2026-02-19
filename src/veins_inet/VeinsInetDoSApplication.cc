#include "veins_inet/VeinsInetDoSApplication.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include <sstream>

using namespace inet;

namespace veins {

Define_Module(VeinsInetDoSApplication);

// Static members for CSV logging
std::ofstream VeinsInetDoSApplication::packetLog;
bool VeinsInetDoSApplication::csvHeaderWritten = false;

VeinsInetDoSApplication::VeinsInetDoSApplication() {
    attackTimer = nullptr;
    totalPacketsSent = 0;
    totalPacketsReceived = 0;
    totalBytesSent = 0;
    totalBytesReceived = 0;
    lastPacketTime = 0;
    firstPacketTime = -1;
    sumInterArrivalTime = 0;
    sumSquaredInterArrivalTime = 0;
    iatCount = 0;
}

VeinsInetDoSApplication::~VeinsInetDoSApplication() {
    cancelAndDelete(attackTimer);
}

void VeinsInetDoSApplication::initialize(int stage) {
    VeinsInetApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Read parameters
        isAttacker = par("isAttacker").boolValue();
        attackInterval = par("attackInterval");
        attackPacketSize = par("attackPacketSize");
        attackStartTime = par("attackStartTime");
        attackDuration = par("attackDuration");

        // Statistics vectors
        packetsSentVector.setName("packetsSent");
        packetsReceivedVector.setName("packetsReceived");
        bytesReceivedVector.setName("bytesReceived");
        interArrivalTimeVector.setName("interArrivalTime");
        packetSizeVector.setName("packetSize");

        // Create timer
        attackTimer = new cMessage("attackTimer");
        
        // Open CSV file for packet logging (shared across all nodes)
        if (!csvHeaderWritten) {
            packetLog.open("results/packet_communications.csv");
            if (packetLog.is_open()) {
                // Write CSV header
                packetLog << "timestamp,senderNodeId,receiverNodeId,packetSize,";
                packetLog << "interArrivalTime,packetType,isSenderAttacker,label\n";
                csvHeaderWritten = true;
                EV << "CSV log file created: results/packet_communications.csv\n";
            }
        }

        // LOG
        EV << "\n========================================\n";
        if (isAttacker) {
            EV << "!!! ATTACKER NODE: " << getParentModule()->getFullName() << " !!!\n";
            EV << "  Attack start: " << attackStartTime << "s\n";
            EV << "  Attack interval: " << attackInterval << "s\n";
            EV << "  Packet size: " << attackPacketSize << " bytes\n";
            EV << "  Attack duration: " << attackDuration << "s\n";
        } else {
            EV << ">>> VICTIM NODE: " << getParentModule()->getFullName() << " <<<\n";
        }
        EV << "========================================\n\n";
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        // DON'T BIND SOCKET - base class already did it!
        // Just schedule attack
        if (isAttacker) {
            EV << "\n!!! SCHEDULING ATTACK AT t=" << attackStartTime << "s !!!\n\n";
            scheduleAt(attackStartTime, attackTimer);
        } else {
            EV << "\n>>> VICTIM READY <<<\n\n";
        }
    }
}

void VeinsInetDoSApplication::sendDoSPacket() {
    if (simTime() >= attackStartTime + attackDuration) {
        EV << "\n!!! ATTACK FINISHED !!!\n\n";
        return;
    }

    // Create packet name
    char msgName[64];
    sprintf(msgName, "DoS-Attack-%ld", totalPacketsSent);

    // Use base class method to create packet
    auto packet = createPacket(msgName);
    
    // Add payload with VeinsInetSampleMessage
    auto payload = makeShared<VeinsInetSampleMessage>();
    payload->setChunkLength(B(attackPacketSize));
    payload->setRoadId("ATTACK");  // Mark as attack traffic
    
    // Timestamp the payload
    timestampPayload(payload);
    
    // Insert payload into packet
    packet->insertAtBack(payload);

    // Send packet using base class method
    sendPacket(std::move(packet));

    // Update stats
    totalPacketsSent++;
    totalBytesSent += attackPacketSize;
    packetsSentVector.record(totalPacketsSent);

    // LOG
    EV << "\n*** ATTACK #" << totalPacketsSent << " SENT";
    EV << " (" << attackPacketSize << "B) at t=" << simTime() << "s ***\n";

    // Schedule next attack
    scheduleAt(simTime() + attackInterval, attackTimer);
}

void VeinsInetDoSApplication::processPacket(std::shared_ptr<Packet> pk) {
    simtime_t now = simTime();
    
    // Update basic counters
    totalPacketsReceived++;
    totalBytesReceived += pk->getByteLength();
    
    // Record packet size
    int pktSize = pk->getByteLength();
    receivedPacketSizes.push_back(pktSize);
    packetSizeVector.record(pktSize);
    
    // Calculate inter-arrival time
    double iatValue = 0;
    if (firstPacketTime < 0) {
        firstPacketTime = now;
        lastPacketTime = now;
    } else {
        simtime_t iat = now - lastPacketTime;
        iatValue = iat.dbl();
        
        // Record IAT
        interArrivalTimeVector.record(iatValue);
        
        // Update accumulators for mean/variance
        sumInterArrivalTime += iatValue;
        sumSquaredInterArrivalTime += (iatValue * iatValue);
        iatCount++;
        
        // Keep sliding window of arrival times (last 100)
        packetArrivalTimes.push_back(now);
        if (packetArrivalTimes.size() > 100) {
            packetArrivalTimes.pop_front();
        }
        
        lastPacketTime = now;
    }
    
    // Record vectors
    packetsReceivedVector.record(totalPacketsReceived);
    bytesReceivedVector.record(totalBytesReceived);
    
    // Extract sender info from packet name
    std::string packetName = pk->getName();
    int senderNodeId = -1;
    bool isSenderAttacker = false;
    std::string packetType = "NORMAL";
    
    // Parse packet name to get sender node ID
    // Expected format: "DoS-Attack-X" or "broadcast-nodeX"
    if (packetName.find("DoS-Attack") != std::string::npos) {
        senderNodeId = 0;  // Attacker is always node[0]
        isSenderAttacker = true;
        packetType = "ATTACK";
    } else if (packetName.find("node[") != std::string::npos) {
        size_t start = packetName.find("node[") + 5;
        size_t end = packetName.find("]", start);
        if (end != std::string::npos) {
            senderNodeId = std::stoi(packetName.substr(start, end - start));
        }
    }
    
    // Get receiver node ID (this node)
    std::string myName = getParentModule()->getFullName();
    int receiverNodeId = -1;
    if (myName.find("node[") != std::string::npos) {
        size_t start = myName.find("node[") + 5;
        size_t end = myName.find("]", start);
        if (end != std::string::npos) {
            receiverNodeId = std::stoi(myName.substr(start, end - start));
        }
    }
    
    // Log this communication to CSV
    logPacketToCSV(packetName.c_str(), senderNodeId, receiverNodeId, 
                   pktSize, iatValue, packetType.c_str(), isSenderAttacker);

    // LOG
    EV << "+++ PKT RECV: " << pk->getName() << " (" << pktSize << "B)";
    if (iatCount > 0) {
        EV << " IAT=" << iatValue*1000 << "ms";
    }
    EV << " [" << packetType << "] +++\n";

    // Call base class
    VeinsInetApplicationBase::processPacket(pk);
}

void VeinsInetDoSApplication::handleMessageWhenUp(cMessage* msg) {
    if (msg == attackTimer) {
        EV << "\n!!! ATTACK TIMER FIRED !!!\n";
        sendDoSPacket();
    }
    else {
        VeinsInetApplicationBase::handleMessageWhenUp(msg);
    }
}

void VeinsInetDoSApplication::finish() {
    VeinsInetApplicationBase::finish();

    // Calculate simulation duration
    double simDuration = simTime().dbl();
    
    // Calculate rates
    double packetSendRate = (simDuration > 0) ? (totalPacketsSent / simDuration) : 0;
    double packetRecvRate = (simDuration > 0) ? (totalPacketsReceived / simDuration) : 0;
    double bytesSendRate = (simDuration > 0) ? (totalBytesSent / simDuration) : 0;
    double bytesRecvRate = (simDuration > 0) ? (totalBytesReceived / simDuration) : 0;
    
    // Inter-arrival time statistics
    double avgIAT = (iatCount > 0) ? (sumInterArrivalTime / iatCount) : 0;
    double varIAT = 0;
    double stdIAT = 0;
    if (iatCount > 1) {
        varIAT = (sumSquaredInterArrivalTime / iatCount) - (avgIAT * avgIAT);
        stdIAT = sqrt(varIAT > 0 ? varIAT : 0);
    }
    
    // Packet size statistics
    double avgPacketSize = 0;
    double stdPacketSize = 0;
    int minPacketSize = 0;
    int maxPacketSize = 0;
    
    if (!receivedPacketSizes.empty()) {
        int sum = 0;
        minPacketSize = receivedPacketSizes[0];
        maxPacketSize = receivedPacketSizes[0];
        
        for (int size : receivedPacketSizes) {
            sum += size;
            if (size < minPacketSize) minPacketSize = size;
            if (size > maxPacketSize) maxPacketSize = size;
        }
        
        avgPacketSize = (double)sum / receivedPacketSizes.size();
        
        // Calculate std deviation
        double sumSq = 0;
        for (int size : receivedPacketSizes) {
            double diff = size - avgPacketSize;
            sumSq += diff * diff;
        }
        stdPacketSize = sqrt(sumSq / receivedPacketSizes.size());
    }
    
    // Burstiness (coefficient of variation of IAT)
    double burstiness = (avgIAT > 0) ? (stdIAT / avgIAT) : 0;
    
    // Throughput efficiency
    double throughputEfficiency = (totalBytesSent > 0) ? 
        ((double)totalBytesReceived / totalBytesSent) : 0;
    
    // Record all scalars for ML features
    recordScalar("totalPacketsSent", totalPacketsSent);
    recordScalar("totalPacketsReceived", totalPacketsReceived);
    recordScalar("totalBytesSent", totalBytesSent);
    recordScalar("totalBytesReceived", totalBytesReceived);
    
    recordScalar("packetSendRate", packetSendRate);
    recordScalar("packetRecvRate", packetRecvRate);
    recordScalar("bytesSendRate", bytesSendRate);
    recordScalar("bytesRecvRate", bytesRecvRate);
    
    recordScalar("avgInterArrivalTime", avgIAT);
    recordScalar("stdInterArrivalTime", stdIAT);
    recordScalar("varInterArrivalTime", varIAT);
    recordScalar("burstiness", burstiness);
    
    recordScalar("avgPacketSize", avgPacketSize);
    recordScalar("stdPacketSize", stdPacketSize);
    recordScalar("minPacketSize", minPacketSize);
    recordScalar("maxPacketSize", maxPacketSize);
    
    recordScalar("throughputEfficiency", throughputEfficiency);
    recordScalar("activeDuration", (lastPacketTime - firstPacketTime).dbl());
    
    // Attack-specific features
    if (isAttacker) {
        recordScalar("attackInterval", attackInterval.dbl());
        recordScalar("attackDuration", attackDuration.dbl());
        recordScalar("attackPacketSize", attackPacketSize);
    }

    // LOG
    EV << "\n========== FINAL STATS ==========\n";
    if (isAttacker) {
        EV << "NODE TYPE: ATTACKER\n";
        EV << "Packets sent: " << totalPacketsSent << " (" << packetSendRate << " pkt/s)\n";
        EV << "Bytes sent: " << totalBytesSent << " (" << bytesSendRate << " B/s)\n";
    } else {
        EV << "NODE TYPE: VICTIM\n";
        EV << "Packets received: " << totalPacketsReceived << " (" << packetRecvRate << " pkt/s)\n";
        EV << "Bytes received: " << totalBytesReceived << " (" << bytesRecvRate << " B/s)\n";
        EV << "Avg IAT: " << avgIAT << "s, Std: " << stdIAT << "s\n";
        EV << "Avg pkt size: " << avgPacketSize << "B, Std: " << stdPacketSize << "B\n";
    }
    EV << "=================================\n";
    
    // Close CSV file at the end
    if (packetLog.is_open()) {
        packetLog.close();
        EV << "CSV packet log closed.\n";
    }
}

void VeinsInetDoSApplication::logPacketToCSV(const char* senderName, int senderNodeId, 
                                             int receiverNodeId, int packetSize, double iat,
                                             const char* packetType, bool isAttack) {
    if (!packetLog.is_open()) {
        return;
    }
    
    // CSV format: timestamp,senderNodeId,receiverNodeId,packetSize,interArrivalTime,packetType,isSenderAttacker,label
    packetLog << simTime().dbl() << ",";
    packetLog << senderNodeId << ",";
    packetLog << receiverNodeId << ",";
    packetLog << packetSize << ",";
    packetLog << iat << ",";
    packetLog << packetType << ",";
    packetLog << (isAttack ? 1 : 0) << ",";
    packetLog << (isAttack ? "ATTACK" : "NORMAL") << "\n";
    packetLog.flush();  // Ensure data is written immediately
}

} // namespace veins