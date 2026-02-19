// CS app with charging protocol and DoS packet logging

#include "veins_inet/VeinsInetCSChargingApp.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/applications/base/ApplicationPacket_m.h"
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(d) _mkdir(d)
#else
#define MKDIR(d) mkdir(d, 0755)
#endif

using namespace veins;

Define_Module(VeinsInetCSChargingApp);

VeinsInetCSChargingApp::~VeinsInetCSChargingApp()
{
    cancelAndDelete(csBatteryTimer);
    closeCSV();
}

// ============================================================
// Initialization
// ============================================================

void VeinsInetCSChargingApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == inet::INITSTAGE_LOCAL) {
        maxSlots = par("maxSlots");

        // CS battery parameters
        csBatteryCapacity = par("csBatteryCapacity").doubleValueInUnit("Wh");
        double initialCSSoC = par("initialCSSoC");
        currentCSBatteryWh = initialCSSoC * csBatteryCapacity;
        currentCSSoC = initialCSSoC;
        chargingPowerW = par("chargingPowerW").doubleValueInUnit("W");
        gridRechargePowerW = par("gridRechargePowerW").doubleValueInUnit("W");
        totalEnergyDelivered = 0.0;

        // Timer for periodic battery update
        csBatteryTimer = new cMessage("csBatteryTimer");

        packetsReceived = 0;
        chargeRequestsReceived = 0;
        lastPacketTime = 0;
        totalEnergyConsumed = 0.0;

        packetReceivedSignal = registerSignal("packetReceived");
        packetSizeSignal = registerSignal("packetSize");
        interArrivalTimeSignal = registerSignal("interArrivalTime");
        energyConsumptionSignal = registerSignal("energyConsumption");
        txDurationSignal = registerSignal("txDuration");
        chargeRequestReceivedSignal = registerSignal("chargeRequestReceived");
        slotsInUseSignal = registerSignal("slotsInUse");

        initCSV();
    }
}

// ============================================================
// Lifecycle
// ============================================================

void VeinsInetCSChargingApp::handleStartOperation(inet::LifecycleOperation* op)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(portNumber);

    // Set multicast output interface for sending responses
    inet::IInterfaceTable* ift = inet::getModuleFromPar<inet::IInterfaceTable>(
        par("interfaceTableModule"), this);
#if INET_VERSION >= 0x0403
    inet::NetworkInterface* ie = ift->findInterfaceByName("wlan0");
#elif INET_VERSION >= 0x0402
    inet::InterfaceEntry* ie = ift->findInterfaceByName("wlan0");
#else
    inet::InterfaceEntry* ie = ift->getInterfaceByName("wlan0");
#endif
    if (ie) {
        socket.setMulticastOutputInterface(ie->getInterfaceId());
    }

    // Join CS multicast group (224.0.0.2) - for charge requests and attack pkts
    inet::L3AddressResolver().tryResolve("224.0.0.2", csMulticastGroup);
    socket.joinMulticastGroup(csMulticastGroup);

    // Join EV/BSM multicast group (224.0.0.1) - for normal traffic logging
    inet::L3AddressResolver().tryResolve("224.0.0.1", evMulticastGroup);
    socket.joinMulticastGroup(evMulticastGroup);

    EV_INFO << getParentModule()->getFullName() << " CS Charging App started, slots="
            << maxSlots << ", battery=" << currentCSBatteryWh << "/"
            << csBatteryCapacity << " Wh" << endl;

    // Start periodic battery update (1 second interval)
    scheduleAt(simTime() + 1.0, csBatteryTimer);
}

void VeinsInetCSChargingApp::handleStopOperation(inet::LifecycleOperation* op)
{
    cancelEvent(csBatteryTimer);
    socket.close();
    closeCSV();
}

void VeinsInetCSChargingApp::handleCrashOperation(inet::LifecycleOperation* op)
{
    cancelEvent(csBatteryTimer);
    socket.destroy();
    closeCSV();
}

// ============================================================
// Message handling
// ============================================================

void VeinsInetCSChargingApp::handleMessageWhenUp(cMessage* msg)
{
    if (msg == csBatteryTimer) {
        updateCSBattery();
        scheduleAt(simTime() + 1.0, csBatteryTimer);
    }
    else if (socket.belongsToSocket(msg)) {
        socket.processMessage(msg);
    }
    else {
        delete msg;
    }
}

// ============================================================
// Socket data arrived
// ============================================================

void VeinsInetCSChargingApp::socketDataArrived(inet::UdpSocket* sock,
                                                inet::Packet* packet)
{
    int pktSize = packet->getByteLength();
    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();
    packetsReceived++;

    auto srcAddr = packet->getTag<inet::L3AddressInd>()->getSrcAddress();
    std::string pktName = packet->getName();

    // Extract sequence number
    int seqNum = packetsReceived;
    try {
        const auto& payload = packet->peekAtFront<inet::ApplicationPacket>();
        seqNum = payload->getSequenceNumber();
    } catch (...) {}

    // Determine communication type
    std::string commType = "UNKNOWN";
    if (pktName.find("ChargeReq") != std::string::npos) {
        commType = "ChargeReq";
    }
    else if (pktName.find("ChargeDone") != std::string::npos) {
        commType = "ChargeDone";
    }
    else if (pktName.find("EV2CS") != std::string::npos) {
        commType = "EV2CS";
    }
    else if (pktName.find("BSM") != std::string::npos) {
        commType = "BSM";
    }

    // Energy accounting
    double energy = calculateReceiveEnergy(pktSize);
    totalEnergyConsumed += energy;
    double txDur = (pktSize * 8.0) / 6e6;

    emit(packetReceivedSignal, (long)packetsReceived);
    emit(packetSizeSignal, (long)pktSize);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(energyConsumptionSignal, energy);
    emit(txDurationSignal, txDur);

    logCSV(commType.c_str(), pktSize, iat.dbl(), energy,
           srcAddr.str().c_str(), getParentModule()->getFullName(),
           seqNum, pktName.c_str());

    // Handle charging protocol messages
    if (commType == "ChargeReq") {
        // Extract vehicle ID from packet name: "ChargeReq-ev[0]-soc0.15"
        std::string vehicleId = "unknown";
        size_t start = pktName.find("ChargeReq-");
        if (start != std::string::npos) {
            start += 10; // skip "ChargeReq-"
            size_t end = pktName.find("-soc", start);
            if (end != std::string::npos) {
                vehicleId = pktName.substr(start, end - start);
            }
        }
        handleChargeRequest(vehicleId, packet);
    }
    else if (commType == "ChargeDone") {
        // Extract vehicle ID: "ChargeDone-ev[0]"
        std::string vehicleId = "unknown";
        size_t start = pktName.find("ChargeDone-");
        if (start != std::string::npos) {
            vehicleId = pktName.substr(11);
        }
        handleChargeComplete(vehicleId);
    }

    delete packet;
}

void VeinsInetCSChargingApp::socketErrorArrived(inet::UdpSocket* sock,
                                                 inet::Indication* ind)
{
    delete ind;
}

void VeinsInetCSChargingApp::socketClosed(inet::UdpSocket* sock)
{
}

// ============================================================
// CS Battery update (called every 1 second)
// ============================================================

void VeinsInetCSChargingApp::updateCSBattery()
{
    int numCharging = (int)chargingVehicles.size();

    // Energy delivered to EVs this tick (1 second)
    // Each active EV drains chargingPowerW from CS
    double drainWh = (chargingPowerW * numCharging) / 3600.0; // W * 1s / 3600
    currentCSBatteryWh -= drainWh;
    totalEnergyDelivered += drainWh;

    // Grid recharge: CS receives power from the electrical grid
    double gridWh = gridRechargePowerW / 3600.0; // W * 1s / 3600
    currentCSBatteryWh += gridWh;

    // Clamp to [0, capacity]
    if (currentCSBatteryWh < 0) currentCSBatteryWh = 0;
    if (currentCSBatteryWh > csBatteryCapacity) currentCSBatteryWh = csBatteryCapacity;

    currentCSSoC = currentCSBatteryWh / csBatteryCapacity;

    // Log a BATTERY_UPDATE event to CSV (shows CS state every second)
    std::string status = numCharging > 0 ? "CS_DISCHARGING" : "CS_IDLE";
    logCSV(status.c_str(), 0, 0.0, totalEnergyDelivered,
           getParentModule()->getFullName(), "grid",
           0, "BatteryTick");
}

// ============================================================
// Charging protocol
// ============================================================

void VeinsInetCSChargingApp::handleChargeRequest(const std::string& vehicleId,
                                                  inet::Packet* pkt)
{
    chargeRequestsReceived++;
    emit(chargeRequestReceivedSignal, (long)chargeRequestsReceived);

    bool available = ((int)chargingVehicles.size() < maxSlots);

    if (available) {
        chargingVehicles.insert(vehicleId);
    }

    emit(slotsInUseSignal, (long)chargingVehicles.size());

    EV_INFO << getParentModule()->getFullName()
            << " received ChargeReq from " << vehicleId
            << " -> " << (available ? "AVAILABLE" : "BUSY")
            << " (slots: " << chargingVehicles.size() << "/" << maxSlots << ")"
            << endl;

    sendChargeResponse(vehicleId, available);
}

void VeinsInetCSChargingApp::handleChargeComplete(const std::string& vehicleId)
{
    chargingVehicles.erase(vehicleId);
    emit(slotsInUseSignal, (long)chargingVehicles.size());

    EV_INFO << getParentModule()->getFullName()
            << " received ChargeDone from " << vehicleId
            << " (slots: " << chargingVehicles.size() << "/" << maxSlots << ")"
            << endl;
}

void VeinsInetCSChargingApp::sendChargeResponse(const std::string& vehicleId,
                                                 bool available)
{
    std::ostringstream name;
    name << "ChargeResp-" << (available ? "AVAILABLE" : "BUSY")
         << "-" << vehicleId;

    int sz = 100;
    auto payload = inet::makeShared<inet::ApplicationPacket>();
    payload->setChunkLength(inet::B(sz));
    payload->setSequenceNumber(chargeRequestsReceived);

    inet::Packet* pkt = new inet::Packet(name.str().c_str(), payload);

    // Send to EV multicast group so the requesting EV receives it
    inet::L3Address dest = inet::Ipv4Address("224.0.0.1");

    logCSV("ChargeResp", sz, 0.0, 0.0,
           getParentModule()->getFullName(), vehicleId.c_str(),
           chargeRequestsReceived, name.str().c_str());

    socket.sendTo(pkt, dest, portNumber);
}

// ============================================================
// Utility
// ============================================================

double VeinsInetCSChargingApp::calculateReceiveEnergy(int pktSize)
{
    double rxPower = 0.05;  // 50 mW
    double dataRate = 6e6;
    double dur = (pktSize * 8.0) / dataRate;
    double e = rxPower * dur * (1.0 + uniform(-0.15, 0.15));
    return e / 3600.0; // Convert J to Wh
}

inet::Coord VeinsInetCSChargingApp::getMyPosition()
{
    auto mob = dynamic_cast<inet::IMobility*>(
        getParentModule()->getSubmodule("mobility"));
    return mob ? mob->getCurrentPosition() : inet::Coord::ZERO;
}

double VeinsInetCSChargingApp::getMySpeed()
{
    auto mob = dynamic_cast<inet::IMobility*>(
        getParentModule()->getSubmodule("mobility"));
    return mob ? mob->getCurrentVelocity().length() : 0.0;
}

// ============================================================
// CSV logging (same schema as receiver app)
// ============================================================

void VeinsInetCSChargingApp::initCSV()
{
    // Ensure results directory exists (static modules init before OMNeT++ creates it)
    struct stat st;
    if (stat("results", &st) != 0) {
        MKDIR("results");
    }

    const char* cfg = getEnvir()->getConfigEx()->getActiveConfigName();
    std::ostringstream fn;
    fn << "results/" << cfg << "_"
       << getParentModule()->getName()
       << getParentModule()->getIndex() << ".csv";

    csvFilePath = fn.str();
    csvFile.open(csvFilePath.c_str());

    if (!csvFile.is_open()) {
        EV_ERROR << "CS: Failed to open CSV file: " << csvFilePath << endl;
    }

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

void VeinsInetCSChargingApp::logCSV(const char* commType, int pktSize,
    double iat, double energy, const char* srcAddr, const char* tgtAddr,
    int seqNum, const char* pktName)
{
    if (!csvFile.is_open()) return;

    inet::Coord pos = getMyPosition();
    double txDur = (pktSize * 8.0) / 6e6;

    // Determine event type
    std::string eventType = "RECEIVED";
    std::string pktStr(pktName);
    if (pktStr.find("ChargeResp") != std::string::npos) {
        eventType = "SENT";
    }
    else if (pktStr.find("BatteryTick") != std::string::npos) {
        eventType = commType; // CS_IDLE or CS_DISCHARGING
    }

    int numCharging = (int)chargingVehicles.size();

    csvFile << std::fixed << std::setprecision(6)
            << simTime().dbl() << ","
            << eventType << ","
            << getParentModule()->getIndex() << ","
            << getParentModule()->getName() << ","
            << commType << ","
            << pktSize << ","
            << iat << ","
            << currentCSBatteryWh << ","
            << energy << ","
            << srcAddr << ","
            << tgtAddr << ","
            << "0" << ","
            << numCharging << ","
            << seqNum << ","
            << pktName << ","
            << pos.x << ","
            << pos.y << ","
            << "0" << ","
            << txDur << ","
            << numCharging << ","
            << packetsReceived << ","
            << currentCSSoC << "\n";
    csvFile.flush();
}

void VeinsInetCSChargingApp::closeCSV()
{
    if (csvFile.is_open()) csvFile.close();
}

// ============================================================
// finish
// ============================================================

void VeinsInetCSChargingApp::finish()
{
    ApplicationBase::finish();

    recordScalar("packetsReceived", packetsReceived);
    recordScalar("chargeRequestsReceived", chargeRequestsReceived);
    recordScalar("totalEnergyConsumed", totalEnergyConsumed);
    recordScalar("totalEnergyDelivered", totalEnergyDelivered);
    recordScalar("finalCSBatteryWh", currentCSBatteryWh);
    recordScalar("finalCSSoC", currentCSSoC);
    recordScalar("avgPacketRate",
                 simTime() > 0 ? packetsReceived / simTime().dbl() : 0);

    closeCSV();
}
