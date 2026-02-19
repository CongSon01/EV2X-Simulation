// Simple receiver application for CS (Charging Station) and RSU nodes

#include "veins_inet/VeinsInetReceiverApp.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
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

Define_Module(VeinsInetReceiverApp);

VeinsInetReceiverApp::VeinsInetReceiverApp()
{
}

VeinsInetReceiverApp::~VeinsInetReceiverApp()
{
    closeCSVLogging();
}

void VeinsInetReceiverApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);
    
    if (stage == inet::INITSTAGE_LOCAL) {
        packetsReceived = 0;
        lastPacketTime = 0;
        totalEnergyConsumed = 0.0;
        
        packetReceivedSignal = registerSignal("packetReceived");
        packetSizeSignal = registerSignal("packetSize");
        interArrivalTimeSignal = registerSignal("interArrivalTime");
        energyConsumptionSignal = registerSignal("energyConsumption");
        txDurationSignal = registerSignal("txDuration");
        
        initializeCSVLogging();
    }
}

void VeinsInetReceiverApp::handleStartOperation(inet::LifecycleOperation* operation)
{
    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(9001);
    
    // Join appropriate multicast group based on node type
    inet::L3Address mcastAddr;
    std::string nodeTypeName = getParentModule()->getName();  // "cs" or "rsu"
    
    if (nodeTypeName.find("cs") != std::string::npos) {
        inet::L3AddressResolver().tryResolve("224.0.0.2", mcastAddr);
    }
    else if (nodeTypeName.find("rsu") != std::string::npos) {
        inet::L3AddressResolver().tryResolve("224.0.0.3", mcastAddr);
    }
    else {
        EV_ERROR << "Unknown node type: " << nodeTypeName << endl;
        return;
    }
    
    socket.joinMulticastGroup(mcastAddr);
    joinedMulticastGroup = mcastAddr;
    
    // Also join BSM multicast group (224.0.0.1) to receive normal V2X traffic
    // This is needed for binary classification (attack vs normal)
    inet::L3AddressResolver().tryResolve("224.0.0.1", bsmMulticastGroup);
    socket.joinMulticastGroup(bsmMulticastGroup);
}

void VeinsInetReceiverApp::handleStopOperation(inet::LifecycleOperation* operation)
{
    socket.close();
    closeCSVLogging();
}

void VeinsInetReceiverApp::handleCrashOperation(inet::LifecycleOperation* operation)
{
    socket.destroy();
    closeCSVLogging();
}

void VeinsInetReceiverApp::handleMessageWhenUp(cMessage* msg)
{
    if (socket.belongsToSocket(msg)) {
        socket.processMessage(msg);
    }
    else {
        delete msg;
    }
}

void VeinsInetReceiverApp::socketDataArrived(inet::UdpSocket* socket, inet::Packet* packet)
{
    // Accept packets from both the specific multicast group AND BSM group
    auto destAddr = packet->getTag<inet::L3AddressInd>()->getDestAddress();
    if (destAddr != joinedMulticastGroup && destAddr != bsmMulticastGroup) {
        delete packet;
        return;
    }
    
    int pktSize = packet->getByteLength();
    simtime_t iat = simTime() - lastPacketTime;
    lastPacketTime = simTime();
    
    packetsReceived++;
    
    auto srcAddr = packet->getTag<inet::L3AddressInd>()->getSrcAddress();
    
    // Determine communication type from packet name
    std::string pktName = packet->getName();
    std::string commType = "UNKNOWN";
    if (pktName.find("EV2EV") != std::string::npos) commType = "EV2EV";
    else if (pktName.find("EV2CS") != std::string::npos) commType = "EV2CS";
    else if (pktName.find("EV2RSU") != std::string::npos) commType = "EV2RSU";
    else if (pktName.find("BSM") != std::string::npos) commType = "BSM";
    
    // Extract sequence number from packet payload
    int seqNum = packetsReceived;
    try {
        const auto& payload = packet->peekAtFront<inet::ApplicationPacket>();
        seqNum = payload->getSequenceNumber();
    } catch (...) {}
    
    // Calculate receive energy
    double recvEnergy = calculateReceiveEnergy(pktSize);
    totalEnergyConsumed += recvEnergy;
    
    // Compute estimated tx duration (pktSize * 8 / dataRate)
    double txDur = (pktSize * 8.0) / 6e6;
    
    emit(packetReceivedSignal, (long)packetsReceived);
    emit(packetSizeSignal, (long)pktSize);
    emit(interArrivalTimeSignal, iat.dbl());
    emit(energyConsumptionSignal, recvEnergy);
    emit(txDurationSignal, txDur);
    
    logPacketToCSV(commType.c_str(), pktSize, iat.dbl(), recvEnergy,
                  srcAddr.str().c_str(), getParentModule()->getFullName(),
                  seqNum, pktName.c_str());
    
    delete packet;
}

void VeinsInetReceiverApp::socketErrorArrived(inet::UdpSocket* socket, inet::Indication* indication)
{
    delete indication;
}

void VeinsInetReceiverApp::socketClosed(inet::UdpSocket* socket)
{
}

void VeinsInetReceiverApp::initializeCSVLogging()
{
    // Ensure results directory exists (static modules init before OMNeT++ creates it)
    struct stat st;
    if (stat("results", &st) != 0) {
        MKDIR("results");
    }

    std::ostringstream filename;
    
    const char* configName = getEnvir()->getConfigEx()->getActiveConfigName();
    
    filename << "results/" << configName << "_" 
             << getParentModule()->getName() 
             << getParentModule()->getIndex() 
             << ".csv";
    
    csvFilePath = filename.str();
    csvFile.open(csvFilePath.c_str());

    if (!csvFile.is_open()) {
        EV_ERROR << "RSU: Failed to open CSV file: " << csvFilePath << endl;
    }
    
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

double VeinsInetReceiverApp::calculateReceiveEnergy(int pktSize)
{
    // Infrastructure node receive energy model
    // Receive power is typically lower than transmit: ~50mW for processing
    double rxPower = 0.05;   // 50mW receive/processing power
    double dataRate = 6e6;   // 6 Mbps
    double duration = (pktSize * 8.0) / dataRate;
    double energy = rxPower * duration;
    
    // Add noise factor for realistic variation (+/- 15%)
    double noiseFactor = 1.0 + uniform(-0.15, 0.15);
    energy *= noiseFactor;
    
    return energy;
}

void VeinsInetReceiverApp::logPacketToCSV(const char* commType, int pktSize,
                                          double iat, double energy,
                                          const char* srcAddress,
                                          const char* targetAddress,
                                          int seqNum,
                                          const char* pktName)
{
    if (!csvFile.is_open()) {
        return;
    }
    
    // Get position and speed of this node
    inet::Coord myPos = getMyPosition();
    double mySpeed = getMySpeed();
    double txDur = (pktSize * 8.0) / 6e6;
    
    csvFile << std::fixed << std::setprecision(6)
            << simTime().dbl() << ","
            << "RECEIVED" << ","
            << getParentModule()->getIndex() << ","
            << getParentModule()->getName() << ","
            << commType << ","
            << pktSize << ","
            << iat << ","
            << "0" << ","
            << energy << ","
            << srcAddress << ","
            << targetAddress << ","
            << "0" << ","
            << "0" << ","
            << seqNum << ","
            << pktName << ","
            << myPos.x << ","
            << myPos.y << ","
            << mySpeed << ","
            << txDur << ","
            << "0" << ","
            << packetsReceived << "\n";
    
    csvFile.flush();
}

void VeinsInetReceiverApp::closeCSVLogging()
{
    if (csvFile.is_open()) {
        csvFile.close();
    }
}

inet::Coord VeinsInetReceiverApp::getMyPosition()
{
    auto mob = dynamic_cast<inet::IMobility*>(getParentModule()->getSubmodule("mobility"));
    if (mob) return mob->getCurrentPosition();
    return inet::Coord::ZERO;
}

double VeinsInetReceiverApp::getMySpeed()
{
    auto mob = dynamic_cast<inet::IMobility*>(getParentModule()->getSubmodule("mobility"));
    if (mob) return mob->getCurrentVelocity().length();
    return 0.0;
}

void VeinsInetReceiverApp::finish()
{
    ApplicationBase::finish();
    
    recordScalar("packetsReceived", packetsReceived);
    recordScalar("packetsSent", 0);  // Receiver-only node, never sends
    recordScalar("totalEnergyConsumed", totalEnergyConsumed);
    recordScalar("avgPacketRate", simTime() > 0 ? packetsReceived / simTime().dbl() : 0);
    recordScalar("finalBatteryLevel", 0);  // Infrastructure node, no battery
    
    closeCSVLogging();
}
