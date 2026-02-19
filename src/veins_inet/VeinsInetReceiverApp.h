// Simple receiver application for CS (Charging Station) and RSU nodes

#ifndef VEINS_INET_RECEIVER_APP_H
#define VEINS_INET_RECEIVER_APP_H

#include "veins_inet/veins_inet.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/common/geometry/common/Coord.h"
#include <fstream>

namespace veins {

class VEINS_INET_API VeinsInetReceiverApp : public inet::ApplicationBase, public inet::UdpSocket::ICallback
{
  protected:
    inet::UdpSocket socket;
    
    int packetsReceived = 0;
    simtime_t lastPacketTime = 0;
    double totalEnergyConsumed = 0.0;
    
    simsignal_t packetReceivedSignal;
    simsignal_t packetSizeSignal;
    simsignal_t interArrivalTimeSignal;
    simsignal_t energyConsumptionSignal;
    simsignal_t txDurationSignal;
    
    std::ofstream csvFile;
    std::string csvFilePath;
    
    inet::L3Address joinedMulticastGroup;
    inet::L3Address bsmMulticastGroup;  // BSM group 224.0.0.1 for normal traffic
    
  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage* msg) override;
    virtual void finish() override;
    
    virtual void handleStartOperation(inet::LifecycleOperation* operation) override;
    virtual void handleStopOperation(inet::LifecycleOperation* operation) override;
    virtual void handleCrashOperation(inet::LifecycleOperation* operation) override;
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    
    virtual void socketDataArrived(inet::UdpSocket* socket, inet::Packet* packet) override;
    virtual void socketErrorArrived(inet::UdpSocket* socket, inet::Indication* indication) override;
    virtual void socketClosed(inet::UdpSocket* socket) override;
    
    void initializeCSVLogging();
    double calculateReceiveEnergy(int pktSize);
    void logPacketToCSV(const char* commType, int pktSize, double iat,
                        double energy, const char* srcAddress, 
                        const char* targetAddress,
                        int seqNum, const char* pktName);
    inet::Coord getMyPosition();
    double getMySpeed();
    void closeCSVLogging();
    
  public:
    VeinsInetReceiverApp();
    virtual ~VeinsInetReceiverApp();
};

} // namespace veins

#endif
