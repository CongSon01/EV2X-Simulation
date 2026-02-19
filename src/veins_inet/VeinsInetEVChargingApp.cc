// EV app with real-time SoC, charging protocol, and DoS attack

#include "veins_inet/VeinsInetEVChargingApp.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/mobility/contract/IMobility.h"
#include "veins/modules/mobility/traci/TraCICommandInterface.h"
#include <sstream>
#include <iomanip>
#include <cmath>
#include <climits>

using namespace veins;

Define_Module(VeinsInetEVChargingApp);

// ============================================================
// Constructor / Destructor
// ============================================================

VeinsInetEVChargingApp::VeinsInetEVChargingApp()
{
    attackTimer = nullptr;
    packetTimer = nullptr;
    batteryTimer = nullptr;
    normalTrafficTimer = nullptr;
    chargeRetryTimer = nullptr;
    isCharging = false;
    needsCharging = false;
    chargingRequested = false;
    chargeResponseAvailable = false; // CS said AVAILABLE but EV not yet in physical range
    rerouteScheduled = false;          // have not rerouted to CS yet
    positionInitialized = false;
    packetsSent = 0;
    packetsReceived = 0;
    totalEnergyConsumed = 0.0;
    lastPacketTime = 0;
    lastSentTimestamp = 0;
    totalBytesSent = 0;
    totalBytesReceived = 0;
}

VeinsInetEVChargingApp::~VeinsInetEVChargingApp()
{
    cancelAndDelete(attackTimer);
    cancelAndDelete(packetTimer);
    cancelAndDelete(batteryTimer);
    cancelAndDelete(normalTrafficTimer);
    cancelAndDelete(chargeRetryTimer);
    closeCSV();
}

// ============================================================
// Initialization
// ============================================================

void VeinsInetEVChargingApp::initialize(int stage)
{
    VeinsInetApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        // Attack params
        isAttacker = par("isAttacker").boolValue();
        targetType = par("targetType").stdstringValue();
        targetAddress = par("targetAddress").stdstringValue();
        attackStartTime = par("attackStartTime");
        attackDuration = par("attackDuration");
        packetInterval = par("packetInterval");
        packetSize = par("packetSize");

        // Battery params (OMNeT++ auto-converts units)
        batteryCapacity = par("batteryCapacity").doubleValueInUnit("Wh");
        currentSoC = par("initialSoC");
        currentBatteryWh = currentSoC * batteryCapacity;
        energyPerMeter = par("energyPerMeter").doubleValueInUnit("Wh");
        chargingPowerW = par("chargingPowerW").doubleValueInUnit("W");
        socThreshold = par("socThreshold");
        chargingRange = par("chargingRange").doubleValueInUnit("m");
        physicalChargingRange = par("physicalChargingRange").doubleValueInUnit("m");
        csEdgeId = par("csEdgeId").stdstringValue();

        // Display
        sumoColor = par("sumoColor").stdstringValue();

        // Ranges
        ev2evRange = par("ev2evRange").doubleValueInUnit("m");
        ev2csRange = par("ev2csRange").doubleValueInUnit("m");
        ev2rsuRange = par("ev2rsuRange").doubleValueInUnit("m");

        // Timers
        attackTimer = new cMessage("attackTimer");
        packetTimer = new cMessage("packetTimer");
        batteryTimer = new cMessage("batteryTimer");
        normalTrafficTimer = new cMessage("normalTrafficTimer");
        chargeRetryTimer = new cMessage("chargeRetryTimer");

        // Signals
        packetSentSignal = registerSignal("packetSent");
        packetReceivedSignal = registerSignal("packetReceived");
        packetSizeSignal = registerSignal("packetSize");
        interArrivalTimeSignal = registerSignal("interArrivalTime");
        batteryLevelSignal = registerSignal("batteryLevel");
        socSignal = registerSignal("soc");
        energyConsumptionSignal = registerSignal("energyConsumption");
        isChargingSignal = registerSignal("isCharging");
        senderSpeedSignal = registerSignal("senderSpeed");
        txDurationSignal = registerSignal("txDuration");

        initCSV();
    }
    else if (stage == INITSTAGE_APPLICATION_LAYER) {
        // Schedule attack if attacker
        if (isAttacker) {
            scheduleAt(simTime() + attackStartTime, attackTimer);
        }
        // Battery update every 1 second
        scheduleAt(simTime() + 1.0, batteryTimer);
        // Normal BSM traffic with random offset
        scheduleAt(simTime() + 1.0 + uniform(0.0, 0.5), normalTrafficTimer);
    }
}

// ============================================================
// Lifecycle
// ============================================================

void VeinsInetEVChargingApp::handleStartOperation(inet::LifecycleOperation* op)
{
    VeinsInetApplicationBase::handleStartOperation(op);

    // Set SUMO vehicle color via TraCI
    setSumoColor();

    // Set multicast destination based on target
    if (isAttacker) {
        if (targetType == "EV")  destAddress = inet::Ipv4Address("224.0.0.1");
        if (targetType == "CS")  destAddress = inet::Ipv4Address("224.0.0.2");
        if (targetType == "RSU") destAddress = inet::Ipv4Address("224.0.0.3");
    }

    // Also join CS multicast group so we can receive ChargeResponses
    inet::Ipv4Address csGroup("224.0.0.2");
    socket.joinMulticastGroup(csGroup);

    EV_INFO << getParentModule()->getFullName() << " started, SoC="
            << (currentSoC * 100) << "%, attacker=" << isAttacker << endl;
}

// ============================================================
// Message handling
// ============================================================

void VeinsInetEVChargingApp::handleMessageWhenUp(cMessage* msg)
{
    if (msg == attackTimer) {
        startAttack();
    }
    else if (msg == packetTimer) {
        sendAttackPacket();
        // Schedule next attack packet
        if (simTime() < attackStartTime + attackDuration) {
            double jitter = uniform(-0.3, 0.3) * packetInterval.dbl();
            simtime_t next = packetInterval + jitter;
            if (next < 0.002) next = 0.002;
            scheduleAt(simTime() + next, packetTimer);
        }
        else {
            stopAttack();
        }
    }
    else if (msg == chargeRetryTimer) {
        // No response or BUSY timeout -> reset so checkChargingNeed will resend
        EV_INFO << getParentModule()->getFullName()
                << " charge retry timer fired -> resetting request flags" << endl;
        chargingRequested = false;
        chargeResponseAvailable = false;
    }
    else if (msg == batteryTimer) {
        updateBattery();
        checkChargingNeed();
        scheduleAt(simTime() + 1.0, batteryTimer);
    }
    else if (msg == normalTrafficTimer) {
        sendNormalTraffic();
        scheduleAt(simTime() + uniform(0.2, 1.0), normalTrafficTimer);
    }
    else {
        VeinsInetApplicationBase::handleMessageWhenUp(msg);
    }
}

// ============================================================
// Receive packet
// ============================================================

void VeinsInetEVChargingApp::processPacket(std::shared_ptr<inet::Packet> pk)
{
    packetsReceived++;
    int pktSize = pk->getByteLength();
    totalBytesReceived += pktSize;
    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();

    // Receive energy cost
    double recvEnergy = calculatePacketEnergy(pktSize) * 0.1;
    totalEnergyConsumed += recvEnergy;
    currentBatteryWh -= recvEnergy;
    if (currentBatteryWh < 0) currentBatteryWh = 0;
    currentSoC = currentBatteryWh / batteryCapacity;

    // Extract info from packet
    std::string pktName = pk->getName();
    int seqNum = packetsReceived;
    try {
        const auto& payload = pk->peekAtFront<inet::ApplicationPacket>();
        seqNum = payload->getSequenceNumber();
    } catch (...) {}

    auto srcAddr = pk->getTag<inet::L3AddressInd>()->getSrcAddress();

    // Check if this is a ChargeResponse for us
    std::string myName = getParentModule()->getFullName();
    if (pktName.find("ChargeResp") != std::string::npos &&
        pktName.find(myName) != std::string::npos) {
        handleChargeResponse(pktName);
    }

    // Determine comm type
    std::string commType = "UNKNOWN";
    if (pktName.find("EV2EV") != std::string::npos)  commType = "EV2EV";
    else if (pktName.find("EV2CS") != std::string::npos)  commType = "EV2CS";
    else if (pktName.find("EV2RSU") != std::string::npos) commType = "EV2RSU";
    else if (pktName.find("BSM") != std::string::npos)    commType = "BSM";
    else if (pktName.find("ChargeResp") != std::string::npos) commType = "CS2EV";
    else if (pktName.find("ChargeReq") != std::string::npos)  commType = "EV2CS";

    double txDur = (pktSize * 8.0) / 6e6;
    emit(packetSizeSignal, (long)pktSize);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(batteryLevelSignal, currentBatteryWh);
    emit(socSignal, currentSoC);
    emit(energyConsumptionSignal, recvEnergy);
    emit(txDurationSignal, txDur);
    emit(senderSpeedSignal, getMySpeed());

    logCSV("RECEIVED", commType.c_str(), pktSize, iat.dbl(),
           srcAddr.str().c_str(), myName.c_str(), seqNum, pktName.c_str());
}

// ============================================================
// Attack logic
// ============================================================

void VeinsInetEVChargingApp::startAttack()
{
    EV_INFO << "DoS attack started on " << getParentModule()->getFullName() << endl;
    scheduleAt(simTime() + packetInterval, packetTimer);
}

void VeinsInetEVChargingApp::stopAttack()
{
    cancelEvent(packetTimer);
    EV_INFO << "DoS attack ended on " << getParentModule()->getFullName() << endl;
}

void VeinsInetEVChargingApp::sendAttackPacket()
{
    double energy = calculatePacketEnergy(1024);
    if (currentBatteryWh < energy) return;

    if (targetType == "EV") {
        sendToTarget("224.0.0.1", "EV2EV", "EV2EV", "ev[1]");
    }
    else if (targetType == "CS") {
        std::string ta = targetAddress.empty() ? "cs[0]" : targetAddress;
        sendToTarget("224.0.0.2", "EV2CS", "EV2CS", ta.c_str());
    }
    else if (targetType == "RSU") {
        std::string ta = targetAddress.empty() ? "rsu[0]" : targetAddress;
        sendToTarget("224.0.0.3", "EV2RSU", "EV2RSU", ta.c_str());
    }
}

void VeinsInetEVChargingApp::sendToTarget(const char* mcastAddr,
    const char* prefix, const char* commType, const char* destAddr)
{
    destAddress = inet::Ipv4Address(mcastAddr);

    // Variable attack packet sizes
    int r = intuniform(0, 99);
    int sz;
    if (r < 20) sz = intuniform(200, 400);
    else if (r < 55) sz = intuniform(500, 900);
    else sz = intuniform(1000, 1500);

    std::ostringstream name;
    name << prefix << "-" << packetsSent;

    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(sz));
    payload->setSequenceNumber(packetsSent);
    std::unique_ptr<inet::Packet> pkt(new inet::Packet(name.str().c_str(), payload));

    // Energy accounting
    double energy = calculatePacketEnergy(sz);
    totalEnergyConsumed += energy;
    currentBatteryWh -= energy;
    if (currentBatteryWh < 0) currentBatteryWh = 0;
    currentSoC = currentBatteryWh / batteryCapacity;

    packetsSent++;
    totalBytesSent += sz;

    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();

    emit(packetSizeSignal, (long)sz);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(batteryLevelSignal, currentBatteryWh);
    emit(socSignal, currentSoC);
    emit(energyConsumptionSignal, energy);

    logCSV("SENT", commType, sz, iat.dbl(),
           getParentModule()->getFullName(), destAddr, packetsSent - 1,
           name.str().c_str());

    sendPacket(std::move(pkt));
}

void VeinsInetEVChargingApp::sendPacket(std::unique_ptr<inet::Packet> pk)
{
    emit(packetSentSignal, (long)packetsSent);
    socket.sendTo(pk.release(), destAddress, portNumber);
}

// ============================================================
// Battery & Charging
// ============================================================

void VeinsInetEVChargingApp::updateBattery()
{
    inet::Coord curPos = getNodePosition(getParentModule()->getFullName());

    // Driving energy consumption based on distance
    if (positionInitialized) {
        double dist = curPos.distance(lastPosition);
        double driveEnergy = dist * energyPerMeter; // Wh
        currentBatteryWh -= driveEnergy;
        totalEnergyConsumed += driveEnergy;
    }
    lastPosition = curPos;
    positionInitialized = true;

    // Charging: add energy from charger every 1s tick
    if (isCharging) {
        double chargeWh = chargingPowerW / 3600.0; // W * 1s / 3600 = Wh
        currentBatteryWh += chargeWh;
        if (currentBatteryWh > batteryCapacity) {
            currentBatteryWh = batteryCapacity;
        }

        // Log charging event to CSV so is_charging=1 is visible
        logCSV("CHARGING", "CS2EV", 0, 1.0,
               "cs[0]", getParentModule()->getFullName(),
               0, "ChargingTick");
    }

    // Clamp
    if (currentBatteryWh < 0) currentBatteryWh = 0;
    currentSoC = currentBatteryWh / batteryCapacity;

    emit(batteryLevelSignal, currentBatteryWh);
    emit(socSignal, currentSoC);
    emit(isChargingSignal, isCharging);

    // Stop charging when full
    if (isCharging && currentSoC >= 1.0) {
        endCharging();
    }
}

void VeinsInetEVChargingApp::checkChargingNeed()
{
    if (isCharging) return;

    // Flag charging need below threshold
    if (currentSoC <= socThreshold) {
        needsCharging = true;
    }

    if (!needsCharging) return;

    double dist = distanceTo("cs[0]");

    // --- Reroute to CS (called once, or retried if reroute didn't take) ---
    // Use TraCI changeTarget so SUMO computes the shortest path to the CS edge.
    if (traciVehicle && (!rerouteScheduled || dist > chargingRange * 2)) {
        traciVehicle->changeTarget(csEdgeId);
        rerouteScheduled = true;
        // Show white in SUMO: "heading to charger"
        traciVehicle->setColor(TraCIColor(255, 255, 255, 255));
        EV_INFO << getParentModule()->getFullName()
                << " rerouted to CS edge=" << csEdgeId
                << "  dist=" << dist << "m  SoC=" << (currentSoC * 100) << "%" << endl;
    }

    // --- Stage 1: Wireless request (within 802.11p range, not yet requested) ---
    if (dist < chargingRange && !chargingRequested) {
        EV_INFO << getParentModule()->getFullName()
                << " in wireless range (" << dist << "m) -> sending ChargeReq" << endl;
        logCSV("WAITING", "ChargeReq", 0, 0.0,
               getParentModule()->getFullName(), "cs[0]", 0, "WaitingForSlot");
        sendChargeRequest();
        if (traciVehicle) traciVehicle->setSpeed(-1); // keep moving
        return;
    }

    // --- Stage 2: Physical plug-in (CS slot available + physically close) ---
    if (chargeResponseAvailable && dist < physicalChargingRange) {
        EV_INFO << getParentModule()->getFullName()
                << " at CS (" << dist << "m) -> BEGIN CHARGING" << endl;
        beginCharging();
        return;
    }
}

void VeinsInetEVChargingApp::sendChargeRequest()
{
    chargingRequested = true;
    std::string myName = getParentModule()->getFullName();

    std::ostringstream name;
    name << "ChargeReq-" << myName << "-soc" << std::fixed
         << std::setprecision(2) << currentSoC;

    int sz = 100; // Small control packet
    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(sz));
    payload->setSequenceNumber(packetsSent);
    std::unique_ptr<inet::Packet> pkt(new inet::Packet(name.str().c_str(), payload));

    packetsSent++;
    totalBytesSent += sz;

    // Send to CS multicast group
    destAddress = inet::Ipv4Address("224.0.0.2");

    logCSV("SENT", "ChargeReq", sz, 0.0,
           myName.c_str(), "cs[0]", packetsSent - 1, name.str().c_str());

    EV_INFO << myName << " sent ChargeRequest (SoC=" << (currentSoC * 100)
            << "%, dist=" << distanceTo("cs[0]") << "m)" << endl;
    socket.sendTo(pkt.release(), destAddress, portNumber);

    // Schedule retry: if no response in 5s, reset chargingRequested
    cancelEvent(chargeRetryTimer);
    scheduleAt(simTime() + 5.0, chargeRetryTimer);
}

void VeinsInetEVChargingApp::handleChargeResponse(const std::string& pktName)
{
    cancelEvent(chargeRetryTimer);

    if (pktName.find("AVAILABLE") != std::string::npos) {
        // CS has a free slot. Set flag and keep driving to get within physical range.
        chargeResponseAvailable = true;
        EV_INFO << getParentModule()->getFullName()
                << " received AVAILABLE -> driving to CS for physical plug-in ("
                << physicalChargingRange << "m required)" << endl;

        // Keep vehicle moving toward CS (do NOT stop here)
        if (traciVehicle) {
            traciVehicle->setSpeed(-1); // restore SUMO default speed
        }
        // checkChargingNeed() will call beginCharging() once dist < physicalChargingRange
    }
    else if (pktName.find("BUSY") != std::string::npos) {
        // CS is full. Reset so we can retry after 3 seconds.
        chargeResponseAvailable = false;
        EV_INFO << getParentModule()->getFullName()
                << " received BUSY -> keep driving, retry in 3s" << endl;

        // Keep vehicle moving toward CS while waiting for free slot
        if (traciVehicle) {
            traciVehicle->setSpeed(-1);
        }
        scheduleAt(simTime() + 3.0, chargeRetryTimer);
    }
}

void VeinsInetEVChargingApp::beginCharging()
{
    isCharging = true;
    emit(isChargingSignal, true);

    // Stop the vehicle in SUMO
    if (traciVehicle) {
        traciVehicle->setSpeed(0);
        // Blue = charging
        traciVehicle->setColor(TraCIColor(0, 100, 255, 255));
    }

    logCSV("CHARGE_START", "CS2EV", 0, 0.0,
           "cs[0]", getParentModule()->getFullName(),
           0, "ChargeStart");

    EV_INFO << getParentModule()->getFullName()
            << " CHARGING (blue) SoC=" << (currentSoC * 100) << "%" << endl;
}

void VeinsInetEVChargingApp::endCharging()
{
    isCharging = false;
    needsCharging = false;
    chargingRequested = false;
    chargeResponseAvailable = false;
    rerouteScheduled = false;  // allow rerouting next time SoC drops
    emit(isChargingSignal, false);

    logCSV("CHARGE_END", "CS2EV", 0, 0.0,
           "cs[0]", getParentModule()->getFullName(),
           0, "ChargeEnd");

    // Resume speed + restore original color
    if (traciVehicle) {
        traciVehicle->setSpeed(-1);
        traciVehicle->changeTarget("A0B0");
        // Restore color: red for attacker, yellow for normal
        if (isAttacker)
            traciVehicle->setColor(TraCIColor(255, 0, 0, 255));
        else
            traciVehicle->setColor(TraCIColor(255, 255, 0, 255));
    }

    sendChargeComplete();
    EV_INFO << getParentModule()->getFullName() << " DONE charging, SoC="
            << (currentSoC * 100) << "%" << endl;
}

void VeinsInetEVChargingApp::sendChargeComplete()
{
    std::string myName = getParentModule()->getFullName();
    std::ostringstream name;
    name << "ChargeDone-" << myName;

    int sz = 50;
    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(sz));
    payload->setSequenceNumber(packetsSent);
    std::unique_ptr<inet::Packet> pkt(new inet::Packet(name.str().c_str(), payload));

    packetsSent++;
    totalBytesSent += sz;

    destAddress = inet::Ipv4Address("224.0.0.2");

    logCSV("SENT", "ChargeDone", sz, 0.0,
           myName.c_str(), "cs[0]", packetsSent - 1, name.str().c_str());

    socket.sendTo(pkt.release(), destAddress, portNumber);
}

// ============================================================
// Normal BSM traffic
// ============================================================

void VeinsInetEVChargingApp::sendNormalTraffic()
{
    int sz = intuniform(200, 400); // SAE J2735 BSM size range
    double energy = calculatePacketEnergy(sz);
    if (currentBatteryWh < energy) return;

    inet::L3Address bsmDest = inet::Ipv4Address("224.0.0.1");

    std::ostringstream name;
    name << "BSM-" << packetsSent;

    auto payload = makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(sz));
    payload->setSequenceNumber(packetsSent);
    std::unique_ptr<inet::Packet> pkt(new inet::Packet(name.str().c_str(), payload));

    totalEnergyConsumed += energy;
    currentBatteryWh -= energy;
    if (currentBatteryWh < 0) currentBatteryWh = 0;
    currentSoC = currentBatteryWh / batteryCapacity;

    packetsSent++;
    totalBytesSent += sz;

    simtime_t iat = simTime() - lastSentTimestamp;
    lastSentTimestamp = simTime();

    emit(packetSizeSignal, (long)sz);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(batteryLevelSignal, currentBatteryWh);
    emit(socSignal, currentSoC);
    emit(energyConsumptionSignal, energy);
    emit(packetSentSignal, (long)packetsSent);

    logCSV("SENT", "BSM", sz, iat.dbl(),
           getParentModule()->getFullName(), "broadcast",
           packetsSent - 1, name.str().c_str());

    socket.sendTo(pkt.release(), bsmDest, portNumber);

    if (!isCharging && !needsCharging && (packetsSent % 2 == 0)) {
            if (traciVehicle) {
                const char* randomEdges[] = {"A0B0", "A2B2"};
                int randomIndex = intuniform(0, 1);

                traciVehicle->changeTarget(randomEdges[randomIndex]);
            }
    }
}

// ============================================================
// SUMO color
// ============================================================

void VeinsInetEVChargingApp::setSumoColor()
{
    if (!traciVehicle) return;

    if (sumoColor == "red") {
        traciVehicle->setColor(TraCIColor(255, 0, 0, 255));
    }
    else {
        traciVehicle->setColor(TraCIColor(255, 255, 0, 255));
    }
}

// ============================================================
// Utility
// ============================================================

double VeinsInetEVChargingApp::calculatePacketEnergy(int pktSize)
{
    double txPower = 0.1;   // 100 mW
    double dataRate = 6e6;  // 6 Mbps
    double dur = (pktSize * 8.0) / dataRate;
    double e = txPower * dur;
    e *= (1.0 + uniform(-0.2, 0.2));
    // Convert Joules to Wh: 1 Wh = 3600 J
    return e / 3600.0;
}

inet::Coord VeinsInetEVChargingApp::getNodePosition(const char* nodeName)
{
    // Search from network level (ev[0], cs[0], rsu[0] are direct children)
    cModule* mod = getSystemModule()->getModuleByPath(nodeName);
    if (!mod) mod = getParentModule(); // fallback: own EV module

    auto mob = dynamic_cast<inet::IMobility*>(mod->getSubmodule("mobility"));
    return mob ? mob->getCurrentPosition() : inet::Coord::ZERO;
}

double VeinsInetEVChargingApp::getMySpeed()
{
    auto mob = dynamic_cast<inet::IMobility*>(
        getParentModule()->getSubmodule("mobility"));
    return mob ? mob->getCurrentVelocity().length() : 0.0;
}

double VeinsInetEVChargingApp::distanceTo(const char* nodeName)
{
    inet::Coord myPos = getNodePosition(getParentModule()->getFullName());
    inet::Coord tgtPos = getNodePosition(nodeName);
    return myPos.distance(tgtPos);
}

// ============================================================
// CSV logging (same 21-column schema as original)
// ============================================================

void VeinsInetEVChargingApp::initCSV()
{
    const char* cfg = getEnvir()->getConfigEx()->getActiveConfigName();
    std::ostringstream fn;
    fn << "results/" << cfg << "_ev" << getParentModule()->getIndex() << ".csv";
    csvFilePath = fn.str();
    csvFile.open(csvFilePath.c_str());

    if (csvFile.is_open()) {
        csvFile << "timestamp,event_type,node_id,node_type,communication_type,"
                << "packet_size,inter_arrival_time,battery_level,"
                << "energy_consumption,source_address,target_address,"
                << "is_attacker,is_charging,"
                << "sequence_number,packet_name,"
                << "pos_x,pos_y,speed,"
                << "tx_duration_est,"
                << "cumulative_packets_sent,cumulative_packets_received,"
                << "soc\n";
    }
}

void VeinsInetEVChargingApp::logCSV(const char* eventType, const char* commType,
    int pktSize, double iat, const char* srcAddr, const char* tgtAddr,
    int seqNum, const char* pktName)
{
    if (!csvFile.is_open()) return;

    inet::Coord pos = getNodePosition(getParentModule()->getFullName());
    double spd = getMySpeed();
    double txDur = (pktSize * 8.0) / 6e6;

    csvFile << std::fixed << std::setprecision(6)
            << simTime().dbl() << ","
            << eventType << ","
            << getParentModule()->getIndex() << ","
            << getParentModule()->getName() << ","
            << commType << ","
            << pktSize << ","
            << iat << ","
            << currentBatteryWh << ","
            << totalEnergyConsumed << ","
            << srcAddr << ","
            << tgtAddr << ","
            << (isAttacker ? "1" : "0") << ","
            << (isCharging ? "1" : "0") << ","
            << seqNum << ","
            << pktName << ","
            << pos.x << ","
            << pos.y << ","
            << spd << ","
            << txDur << ","
            << packetsSent << ","
            << packetsReceived << ","
            << currentSoC << "\n";
    csvFile.flush();
}

void VeinsInetEVChargingApp::closeCSV()
{
    if (csvFile.is_open()) csvFile.close();
}

// ============================================================
// finish()
// ============================================================

void VeinsInetEVChargingApp::finish()
{
    VeinsInetApplicationBase::finish();

    recordScalar("packetsSent", packetsSent);
    recordScalar("packetsReceived", packetsReceived);
    recordScalar("totalEnergyConsumed", totalEnergyConsumed);
    recordScalar("finalBatteryWh", currentBatteryWh);
    recordScalar("finalSoC", currentSoC);
    recordScalar("totalBytesSent", (double)totalBytesSent);
    recordScalar("totalBytesReceived", (double)totalBytesReceived);

    double dur = simTime().dbl();
    recordScalar("packetSendRate", dur > 0 ? packetsSent / dur : 0);
    recordScalar("packetRecvRate", dur > 0 ? packetsReceived / dur : 0);
    recordScalar("attackDurationParam", attackDuration.dbl());
    recordScalar("isAttackerParam", isAttacker ? 1.0 : 0.0);

    closeCSV();
}
