// CS app with charging protocol and DoS packet logging

#ifndef __VEINS_INET_CSCHARGINGAPP_H_
#define __VEINS_INET_CSCHARGINGAPP_H_

#include "veins_inet/veins_inet.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/mobility/contract/IMobility.h"
#include "inet/common/geometry/common/Coord.h"
#include <fstream>
#include <set>

namespace veins {

class VEINS_INET_API VeinsInetCSChargingApp
    : public inet::ApplicationBase
    , public inet::UdpSocket::ICallback
{
protected:
    inet::UdpSocket socket;
    const int portNumber = 9001;

    // Charging slots
    int maxSlots;
    std::set<std::string> chargingVehicles; // currently charging

    // CS battery model
    double csBatteryCapacity;    // Wh (max capacity)
    double currentCSBatteryWh;   // Wh (current stored energy)
    double currentCSSoC;         // 0.0 to 1.0
    double chargingPowerW;       // W delivered to each EV
    double gridRechargePowerW;   // W received continuously from the grid
    double totalEnergyDelivered; // Wh cumulative energy sent to EVs

    // Timer for periodic CS battery update (1s)
    cMessage* csBatteryTimer;

    // Stats
    int packetsReceived = 0;
    int chargeRequestsReceived = 0;
    simtime_t lastPacketTime = 0;
    double totalEnergyConsumed = 0.0;

    // Signals
    simsignal_t packetReceivedSignal;
    simsignal_t packetSizeSignal;
    simsignal_t interArrivalTimeSignal;
    simsignal_t energyConsumptionSignal;
    simsignal_t txDurationSignal;
    simsignal_t chargeRequestReceivedSignal;
    simsignal_t slotsInUseSignal;

    // Multicast groups
    inet::L3Address csMulticastGroup;
    inet::L3Address evMulticastGroup;

    // CSV
    std::ofstream csvFile;
    std::string csvFilePath;

protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleStartOperation(inet::LifecycleOperation* op) override;
    virtual void handleStopOperation(inet::LifecycleOperation* op) override;
    virtual void handleCrashOperation(inet::LifecycleOperation* op) override;
    virtual void handleMessageWhenUp(cMessage* msg) override;

    // Socket callbacks
    virtual void socketDataArrived(inet::UdpSocket* sock, inet::Packet* pkt) override;
    virtual void socketErrorArrived(inet::UdpSocket* sock, inet::Indication* ind) override;
    virtual void socketClosed(inet::UdpSocket* sock) override;

    // Charging protocol
    void handleChargeRequest(const std::string& vehicleId, inet::Packet* pkt);
    void handleChargeComplete(const std::string& vehicleId);
    void sendChargeResponse(const std::string& vehicleId, bool available);

    // CS battery update (called every 1s)
    void updateCSBattery();

    // Utility
    double calculateReceiveEnergy(int pktSize);
    inet::Coord getMyPosition();
    double getMySpeed();

    // CSV
    void initCSV();
    void logCSV(const char* commType, int pktSize, double iat, double energy,
                const char* srcAddr, const char* tgtAddr,
                int seqNum, const char* pktName);
    void closeCSV();

public:
    VeinsInetCSChargingApp() {}
    virtual ~VeinsInetCSChargingApp();
};

} // namespace veins

#endif
