// EV DoS Attack application with battery management and multicast targeting

#include "veins_inet/VeinsInetEVDoSApplication.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/applications/base/ApplicationPacket_m.h"
#include <sstream>
#include <iomanip>
#include <climits>
#include <cmath>
#include "inet/mobility/contract/IMobility.h"

using namespace veins;

Define_Module(VeinsInetEVDoSApplication);

VeinsInetEVDoSApplication::VeinsInetEVDoSApplication()
{
    attackTimer = nullptr;
    packetTimer = nullptr;
    chargingTimer = nullptr;
    normalTrafficTimer = nullptr;
    energyStorage = nullptr;
    isCharging = false;
    packetsSent = 0;
    packetsReceived = 0;
    totalEnergyConsumed = 0.0;
    lastPacketTime = 0;
    lastSentTimestamp = 0;
    totalBytesSent = 0;
    totalBytesReceived = 0;
    minSentPktSize = INT_MAX;
    maxSentPktSize = 0;
    sumIAT = 0.0;
    sumIATSq = 0.0;
    iatCount = 0;
}

VeinsInetEVDoSApplication::~VeinsInetEVDoSApplication()
{
    cancelAndDelete(attackTimer);
    cancelAndDelete(packetTimer);
    cancelAndDelete(chargingTimer);
    cancelAndDelete(normalTrafficTimer);
    closeCSVLogging();
}

void VeinsInetEVDoSApplication::initialize(int stage)
{
    VeinsInetApplicationBase::initialize(stage);
    
    if (stage == INITSTAGE_LOCAL) {
        // Read parameters
        isAttacker = par("isAttacker").boolValue();
        targetType = par("targetType").stdstringValue();
        targetAddress = par("targetAddress").stdstringValue();
        attackStartTime = par("attackStartTime");
        attackDuration = par("attackDuration");
        packetInterval = par("packetInterval");
        packetSize = par("packetSize");
        
        // EV energy parameters - OMNeT++ auto-converts units to base unit (J for energy)
        batteryCapacity = par("batteryCapacity");  // Already in Joules
        currentBatteryLevel = par("initialBatteryLevel");  // Already in Joules
        chargingPower = par("chargingPower");
        chargingThreshold = par("chargingThreshold");  // Already in Joules
        
        // Communication ranges
        ev2evRange = par("ev2evRange");
        ev2csRange = par("ev2csRange");
        ev2rsuRange = par("ev2rsuRange");
        
        // Initialize timers
        attackTimer = new cMessage("attackTimer");
        packetTimer = new cMessage("packetTimer");
        chargingTimer = new cMessage("chargingTimer");
        normalTrafficTimer = new cMessage("normalTrafficTimer");
        
        // Register signals
        packetSentSignal = registerSignal("packetSent");
        packetReceivedSignal = registerSignal("packetReceived");
        packetSizeSignal = registerSignal("packetSize");
        interArrivalTimeSignal = registerSignal("interArrivalTime");
        batteryLevelSignal = registerSignal("batteryLevel");
        energyConsumptionSignal = registerSignal("energyConsumption");
        communicationTypeSignal = registerSignal("communicationType");
        isChargingSignal = registerSignal("isCharging");
        senderSpeedSignal = registerSignal("senderSpeed");
        txDurationSignal = registerSignal("txDuration");
        
        // Initialize CSV logging
        initializeCSVLogging();
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        // Try to get energy storage reference (optional, for display only)
        cModule* energyMod = getModuleByPath("^.energyStorage");
        if (energyMod != nullptr) {
            energyStorage = dynamic_cast<power::SimpleEpEnergyStorage*>(energyMod);
        }
        
        // Schedule attack start if this is attacker
        if (isAttacker) {
            scheduleAt(simTime() + attackStartTime, attackTimer);
        }
        
        // Schedule periodic battery check
        scheduleAt(simTime() + 1.0, chargingTimer);
        
        // Schedule normal V2X background traffic for ALL EVs
        // Start after 1s with random offset to avoid synchronization
        double startOffset = 1.0 + uniform(0.0, 0.5);
        scheduleAt(simTime() + startOffset, normalTrafficTimer);
    }
}

void VeinsInetEVDoSApplication::handleStartOperation(inet::LifecycleOperation* operation)
{
    VeinsInetApplicationBase::handleStartOperation(operation);
    
    if (isAttacker) {
        if (targetType == "EV") {
            destAddress = inet::Ipv4Address("224.0.0.1");
        }
        else if (targetType == "CS") {
            destAddress = inet::Ipv4Address("224.0.0.2");
        }
        else if (targetType == "RSU") {
            destAddress = inet::Ipv4Address("224.0.0.3");
        }
    }
    
    EV_INFO << "EV DoS Application started on " << getParentModule()->getFullName() << endl;
}

void VeinsInetEVDoSApplication::handleMessageWhenUp(cMessage* msg)
{
    if (msg == attackTimer) {
        startAttack();
    }
    else if (msg == packetTimer) {
        sendAttackPacket();
        
        // Schedule next packet if attack still active
        if (simTime() < attackStartTime + attackDuration) {
            // Add jitter to packet interval (+/- 30%) for realistic DoS pattern
            // Real attackers don't send at perfectly constant intervals
            double jitter = uniform(-0.3, 0.3) * packetInterval.dbl();
            simtime_t nextInterval = packetInterval + jitter;
            if (nextInterval < 0.002) nextInterval = 0.002;  // Min 2ms
            scheduleAt(simTime() + nextInterval, packetTimer);
        }
        else {
            stopAttack();
        }
    }
    else if (msg == chargingTimer) {
        updateBatteryLevel();
        checkChargingNeed();
        
        // Reschedule battery check
        scheduleAt(simTime() + 1.0, chargingTimer);
    }
    else if (msg == normalTrafficTimer) {
        sendNormalTraffic();
        
        // Schedule next normal packet: BSM-like 1-5 Hz with jitter
        double normalInterval = uniform(0.2, 1.0);  // 1-5 Hz V2X BSM rate
        scheduleAt(simTime() + normalInterval, normalTrafficTimer);
    }
    else {
        // Pass to base class for socket processing
        VeinsInetApplicationBase::handleMessageWhenUp(msg);
    }
}

void VeinsInetEVDoSApplication::processPacket(std::shared_ptr<inet::Packet> pk)
{
    packetsReceived++;
    int pktSize = pk->getByteLength();
    totalBytesReceived += pktSize;
    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();
    
    double recvEnergy = calculatePacketEnergy(pktSize) * 0.1;
    totalEnergyConsumed += recvEnergy;
    currentBatteryLevel -= recvEnergy;
    
    // Extract sequence number from packet payload
    int seqNum = packetsReceived;
    try {
        const auto& payload = pk->peekAtFront<inet::ApplicationPacket>();
        seqNum = payload->getSequenceNumber();
    } catch (...) {}
    
    std::string pktName = pk->getName();
    
    // Compute estimated tx duration (visible in Qtenv as "duration")
    double txDur = (pktSize * 8.0) / 6e6;
    
    emit(packetSizeSignal, (long)pktSize);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(batteryLevelSignal, currentBatteryLevel);
    emit(energyConsumptionSignal, recvEnergy);
    emit(txDurationSignal, txDur);
    emit(senderSpeedSignal, getMySpeed());
    
    auto srcAddr = pk->getTag<inet::L3AddressInd>()->getSrcAddress();
    
    // Determine communication type from packet name
    std::string commType = "UNKNOWN";
    if (pktName.find("EV2EV") != std::string::npos) commType = "EV2EV";
    else if (pktName.find("EV2CS") != std::string::npos) commType = "EV2CS";
    else if (pktName.find("EV2RSU") != std::string::npos) commType = "EV2RSU";
    else if (pktName.find("BSM") != std::string::npos) commType = "BSM";
    
    logPacketToCSV("RECEIVED", commType.c_str(), pktSize, iat.dbl(), 
                  currentBatteryLevel, recvEnergy, 
                  srcAddr.str().c_str(), getParentModule()->getFullName(),
                  seqNum, pktName.c_str());
}

void VeinsInetEVDoSApplication::startAttack()
{
    scheduleAt(simTime() + packetInterval, packetTimer);
}

void VeinsInetEVDoSApplication::sendPacket(std::unique_ptr<inet::Packet> pk)
{
    emit(packetSentSignal, (long)packetsSent);
    socket.sendTo(pk.release(), destAddress, portNumber);
}

void VeinsInetEVDoSApplication::stopAttack()
{
    cancelEvent(packetTimer);
}

void VeinsInetEVDoSApplication::sendAttackPacket()
{
    // Check battery using estimated energy for average packet size
    double sendEnergy = calculatePacketEnergy(1024);
    if (currentBatteryLevel < sendEnergy) {
        return;
    }
    
    if (targetType == "EV") {
        sendToEV("ev[1]");
    }
    else if (targetType == "CS") {
        sendToCS(targetAddress.c_str());
    }
    else if (targetType == "RSU") {
        sendToRSU(targetAddress.c_str());
    }
    else if (targetType == "Mixed") {
        sendMixedAttack();
    }
}

void VeinsInetEVDoSApplication::sendToEV(const char* destAddr)
{
    sendToTarget("224.0.0.1", "EV2EV", "EV2EV", destAddr);
}

void VeinsInetEVDoSApplication::sendToCS(const char* destAddr)
{
    sendToTarget("224.0.0.2", "EV2CS", "EV2CS", destAddr);
}

void VeinsInetEVDoSApplication::sendToRSU(const char* destAddr)
{
    sendToTarget("224.0.0.3", "EV2RSU", "EV2RSU", destAddr);
}

void VeinsInetEVDoSApplication::sendNormalTraffic()
{
    // Generate normal V2X BSM (Basic Safety Message) traffic
    // SAE J2735: BSM Part I = 39 bytes header + variable Part II
    // Continuous distribution 200-400 bytes for realistic variation
    int normalPktSize = intuniform(200, 400);
    
    double sendEnergy = calculatePacketEnergy(normalPktSize);
    if (currentBatteryLevel < sendEnergy) {
        return;
    }
    
    // Normal traffic goes to EV multicast group (V2V communication)
    inet::L3Address normalDest = inet::Ipv4Address("224.0.0.1");
    
    std::ostringstream str;
    str << "BSM-" << packetsSent;
    
    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(normalPktSize));
    payload->setSequenceNumber(packetsSent);
    
    std::unique_ptr<inet::Packet> packet(new inet::Packet(str.str().c_str(), payload));
    
    packetsSent++;
    totalBytesSent += normalPktSize;
    if (normalPktSize < minSentPktSize) minSentPktSize = normalPktSize;
    if (normalPktSize > maxSentPktSize) maxSentPktSize = normalPktSize;
    
    totalEnergyConsumed += sendEnergy;
    currentBatteryLevel -= sendEnergy;
    
    simtime_t iat = simTime() - lastSentTimestamp;
    lastSentTimestamp = simTime();
    double iatVal = iat.dbl();
    sumIAT += iatVal;
    sumIATSq += iatVal * iatVal;
    iatCount++;
    
    emit(packetSizeSignal, (long)normalPktSize);
    emit(interArrivalTimeSignal, iatVal);
    emit(batteryLevelSignal, currentBatteryLevel);
    emit(energyConsumptionSignal, sendEnergy);
    
    // Log as SENT with communication type "BSM" (normal V2X)
    logPacketToCSV("SENT", "BSM", normalPktSize, iatVal, 
                  currentBatteryLevel, sendEnergy, 
                  getParentModule()->getFullName(), "broadcast",
                  packetsSent - 1, str.str().c_str());
    
    emit(packetSentSignal, (long)packetsSent);
    socket.sendTo(packet.release(), normalDest, portNumber);
}

void VeinsInetEVDoSApplication::sendToTarget(const char* mcastAddr, 
                                             const char* prefix, 
                                             const char* commType, 
                                             const char* destAddr)
{
    destAddress = inet::Ipv4Address(mcastAddr);
    
    // Variable attack packet sizes with partial overlap to normal BSM range
    // Realistic DoS: sophisticated attackers may vary packet sizes
    // 20% overlap with BSM (200-400B), 35% medium (500-900B), 45% large (1000-1500B)
    int r = intuniform(0, 99);
    int actualPktSize;
    if (r < 20) actualPktSize = intuniform(200, 400);        // Overlaps with BSM
    else if (r < 55) actualPktSize = intuniform(500, 900);   // Medium flood
    else actualPktSize = intuniform(1000, 1500);             // Large flood
    
    std::ostringstream str;
    str << prefix << "-" << packetsSent;
    
    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(actualPktSize));
    payload->setSequenceNumber(packetsSent);
    
    std::unique_ptr<inet::Packet> packet(new inet::Packet(str.str().c_str(), payload));
    
    packetsSent++;
    totalBytesSent += actualPktSize;
    if (actualPktSize < minSentPktSize) minSentPktSize = actualPktSize;
    if (actualPktSize > maxSentPktSize) maxSentPktSize = actualPktSize;
    
    double sendEnergy = calculatePacketEnergy(actualPktSize);
    totalEnergyConsumed += sendEnergy;
    currentBatteryLevel -= sendEnergy;
    
    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();
    double iatVal = iat.dbl();
    sumIAT += iatVal;
    sumIATSq += iatVal * iatVal;
    iatCount++;
    
    emit(packetSizeSignal, (long)actualPktSize);
    emit(interArrivalTimeSignal, iatVal);
    emit(batteryLevelSignal, currentBatteryLevel);
    emit(energyConsumptionSignal, sendEnergy);
    emit(communicationTypeSignal, commType);
    
    logPacketToCSV("SENT", commType, actualPktSize, iatVal, 
                  currentBatteryLevel, sendEnergy, 
                  getParentModule()->getFullName(), destAddr,
                  packetsSent - 1, str.str().c_str());
    
    sendPacket(std::move(packet));
}

void VeinsInetEVDoSApplication::sendMixedAttack()
{
    // Randomly choose target type
    int choice = intuniform(0, 2, 0);
    
    if (choice == 0) {
        sendToEV("ev[1]");
    }
    else if (choice == 1) {
        sendToCS("cs[0]");
    }
    else {
        sendToRSU("rsu[0]");
    }
}

void VeinsInetEVDoSApplication::updateBatteryLevel()
{
    if (isCharging) {
        double chargeAmount = chargingPower * 1.0;
        currentBatteryLevel += chargeAmount;
        if (currentBatteryLevel > batteryCapacity) {
            currentBatteryLevel = batteryCapacity;
        }
    }
    
    emit(batteryLevelSignal, currentBatteryLevel);
}

void VeinsInetEVDoSApplication::checkChargingNeed()
{
    if (currentBatteryLevel < chargingThreshold && !isCharging) {
        inet::Coord csPos = getNodePosition("cs[0]");
        inet::Coord myPos = getNodePosition(getParentModule()->getFullName());
        
        if (isInRange(csPos, ev2csRange)) {
            startCharging();
        }
    }
    else if (isCharging && currentBatteryLevel >= batteryCapacity * 0.9) {
        stopCharging();
    }
}

void VeinsInetEVDoSApplication::startCharging()
{
    isCharging = true;
    emit(isChargingSignal, true);
}

void VeinsInetEVDoSApplication::stopCharging()
{
    isCharging = false;
    emit(isChargingSignal, false);
}

double VeinsInetEVDoSApplication::calculatePacketEnergy(int pktSize)
{
    double txPower = 0.1;  // 100mW transmit power
    double dataRate = 6e6; // 6 Mbps data rate
    double duration = (pktSize * 8.0) / dataRate;
    double energy = txPower * duration;
    
    // Add realistic noise (+/- 20%) for channel conditions, retransmissions
    double noiseFactor = 1.0 + uniform(-0.2, 0.2);
    energy *= noiseFactor;
    
    return energy;
}

bool VeinsInetEVDoSApplication::isInRange(inet::Coord targetPos, double range)
{
    inet::Coord myPos = getNodePosition(getParentModule()->getFullName());
    double distance = myPos.distance(targetPos);
    return distance <= range;
}

inet::Coord VeinsInetEVDoSApplication::getNodePosition(const char* nodeName)
{
    cModule* targetModule = getModuleByPath(nodeName);
    if (targetModule == nullptr) {
        targetModule = getParentModule();
    }
    
    auto mobility = check_and_cast<inet::IMobility*>(
        targetModule->getSubmodule("mobility"));
    
    if (mobility != nullptr) {
        return mobility->getCurrentPosition();
    }
    
    return inet::Coord::ZERO;
}

std::string VeinsInetEVDoSApplication::determineCommType(const char* destAddr)
{
    std::string addr(destAddr);
    
    if (addr.find("ev") != std::string::npos) {
        return "EV2EV";
    }
    else if (addr.find("cs") != std::string::npos) {
        return "EV2CS";
    }
    else if (addr.find("rsu") != std::string::npos) {
        return "EV2RSU";
    }
    
    return "UNKNOWN";
}

double VeinsInetEVDoSApplication::getMySpeed()
{
    cModule* parentMod = getParentModule();
    if (!parentMod) return 0.0;
    
    auto mobility = dynamic_cast<inet::IMobility*>(parentMod->getSubmodule("mobility"));
    if (mobility != nullptr) {
        return mobility->getCurrentVelocity().length();
    }
    return 0.0;
}

void VeinsInetEVDoSApplication::initializeCSVLogging()
{
    std::ostringstream filename;
    
    const char* configName = getEnvir()->getConfigEx()->getActiveConfigName();
    
    filename << "results/" << configName << "_ev" 
             << getParentModule()->getIndex() 
             << ".csv";
    
    csvFilePath = filename.str();
    csvFile.open(csvFilePath.c_str());
    
    if (csvFile.is_open()) {
        csvFile << "timestamp,event_type,node_id,node_type,communication_type,"
                << "packet_size,inter_arrival_time,battery_level,"
                << "energy_consumption,source_address,target_address,"
                << "is_attacker,is_charging,"
                << "sequence_number,packet_name,"
                << "pos_x,pos_y,speed,"
                << "tx_duration_est,"
                << "cumulative_packets_sent,cumulative_packets_received\n";
    }
}

void VeinsInetEVDoSApplication::logPacketToCSV(const char* eventType, 
                                               const char* commType,
                                               int pktSize, 
                                               double iat, 
                                               double battery,
                                               double energy, 
                                               const char* srcAddress,
                                               const char* targetAddress,
                                               int seqNum,
                                               const char* pktName)
{
    if (!csvFile.is_open()) {
        return;
    }
    
    // Get position and speed of this node
    inet::Coord myPos = getNodePosition(getParentModule()->getFullName());
    double mySpeed = getMySpeed();
    double txDur = (pktSize * 8.0) / 6e6;
    
    csvFile << std::fixed << std::setprecision(6)
            << simTime().dbl() << ","
            << eventType << ","
            << getParentModule()->getIndex() << ","
            << getParentModule()->getName() << ","
            << commType << ","
            << pktSize << ","
            << iat << ","
            << battery << ","
            << energy << ","
            << srcAddress << ","
            << targetAddress << ","
            << (isAttacker ? "1" : "0") << ","
            << (isCharging ? "1" : "0") << ","
            << seqNum << ","
            << pktName << ","
            << myPos.x << ","
            << myPos.y << ","
            << mySpeed << ","
            << txDur << ","
            << packetsSent << ","
            << packetsReceived << "\n";
    
    csvFile.flush();
}

void VeinsInetEVDoSApplication::closeCSVLogging()
{
    if (csvFile.is_open()) {
        csvFile.close();
    }
}

void VeinsInetEVDoSApplication::finish()
{
    VeinsInetApplicationBase::finish();
    
    // Basic counters
    recordScalar("packetsSent", packetsSent);
    recordScalar("packetsReceived", packetsReceived);
    recordScalar("totalEnergyConsumed", totalEnergyConsumed);
    recordScalar("finalBatteryLevel", currentBatteryLevel);
    
    // Byte-level stats
    recordScalar("totalBytesSent", (double)totalBytesSent);
    recordScalar("totalBytesReceived", (double)totalBytesReceived);
    
    // Rate metrics
    double simDur = simTime().dbl();
    recordScalar("packetSendRate", simDur > 0 ? packetsSent / simDur : 0);
    recordScalar("packetRecvRate", simDur > 0 ? packetsReceived / simDur : 0);
    recordScalar("avgPacketRate", simDur > 0 ? packetsSent / simDur : 0);
    recordScalar("bytesSendRate", simDur > 0 ? totalBytesSent / simDur : 0);
    recordScalar("bytesRecvRate", simDur > 0 ? totalBytesReceived / simDur : 0);
    
    // Packet size stats
    double avgPktSize = packetsSent > 0 ? (double)totalBytesSent / packetsSent : 0;
    recordScalar("avgPacketSize", avgPktSize);
    recordScalar("minPacketSize", minSentPktSize == INT_MAX ? 0 : minSentPktSize);
    recordScalar("maxPacketSize", maxSentPktSize);
    
    // Inter-arrival time stats
    double avgIAT = iatCount > 0 ? sumIAT / iatCount : 0;
    double varIAT = iatCount > 1 ? (sumIATSq / iatCount - avgIAT * avgIAT) : 0;
    double stdIAT = varIAT > 0 ? sqrt(varIAT) : 0;
    recordScalar("avgInterArrivalTime", avgIAT);
    recordScalar("stdInterArrivalTime", stdIAT);
    recordScalar("burstiness", avgIAT > 0 ? stdIAT / avgIAT : 0);
    
    // Throughput efficiency: received / sent ratio
    recordScalar("throughputEfficiency",
                 totalBytesSent > 0 ? (double)totalBytesReceived / totalBytesSent : 0);
    
    // Attack config scalars
    recordScalar("attackInterval", packetInterval.dbl());
    recordScalar("attackDuration", attackDuration.dbl());
    recordScalar("attackPacketSize", packetSize);
    recordScalar("activeDuration", simDur);
    
    closeCSVLogging();
}
