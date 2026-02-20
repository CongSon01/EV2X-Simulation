// EV app with real-time SoC, charging protocol, and DoS attack

#ifndef __VEINS_INET_EVCHARGINGAPP_H_
#define __VEINS_INET_EVCHARGINGAPP_H_

#include "veins_inet/VeinsInetApplicationBase.h"
#include "inet/common/geometry/common/Coord.h"
#include "veins/modules/mobility/traci/TraCIColor.h"
#include <fstream>
#include <vector>
#include <string>

using namespace omnetpp;
using namespace inet;

namespace veins {

class VEINS_INET_API VeinsInetEVChargingApp : public VeinsInetApplicationBase
{
protected:
    // Attack config
    bool isAttacker;
    std::string targetType;
    std::string targetAddress;
    simtime_t attackStartTime;
    simtime_t attackDuration;
    simtime_t packetInterval;
    int packetSize;

    // Battery state
    double batteryCapacity;    // Wh
    double currentSoC;         // 0.0 to 1.0
    double currentBatteryWh;   // Wh
    double energyPerMeter;     // Wh per meter driven
    double chargingPowerW;     // Watts
    double socThreshold;            // ratio (0.2 = 20%)
    double chargingRange;           // meters: wireless range to send ChargeReq
    double physicalChargingRange;   // meters: must be THIS close to physically charge
    std::string csEdgeId;           // SUMO edge id at the CS location (for rerouting)

    // Charging state machine
    bool needsCharging;
    bool chargingRequested;
    bool chargeResponseAvailable;   // CS said AVAILABLE; waiting for physical proximity
    bool isCharging;
    bool rerouteScheduled;          // true after we issued changeTarget() to CS

    // Dead battery
    bool batteryDead;               // true when Wh reaches 0; vehicle stops permanently

    // Destination cycling (keeps vehicle alive after charging/reroute)
    std::vector<std::string> destList;  // post-charge waypoints (edges)
    int destIndex;                      // next waypoint index

    // Rate limiting
    int maxPktPerSecond;            // max recv pkts/s (0=unlimited)
    int pktsReceivedThisSec;        // rolling counter, reset every 1s
    cMessage* secTimer;             // 1-second reset timer

    // Display
    std::string sumoColor;

    // Ranges
    double ev2evRange;
    double ev2csRange;
    double ev2rsuRange;

    // Position tracking
    inet::Coord lastPosition;
    bool positionInitialized;

    // Timers
    cMessage* attackTimer;
    cMessage* packetTimer;
    cMessage* batteryTimer;       // 1-second periodic battery update
    cMessage* normalTrafficTimer;
    cMessage* chargeRetryTimer;   // Retry charge request if no response

    // Signals
    simsignal_t packetSentSignal;
    simsignal_t packetReceivedSignal;
    simsignal_t packetSizeSignal;
    simsignal_t interArrivalTimeSignal;
    simsignal_t batteryLevelSignal;
    simsignal_t socSignal;
    simsignal_t energyConsumptionSignal;
    simsignal_t isChargingSignal;
    simsignal_t senderSpeedSignal;
    simsignal_t txDurationSignal;

    // Stats
    simtime_t lastPacketTime;
    simtime_t lastSentTimestamp;
    int packetsSent;
    int packetsReceived;
    double totalEnergyConsumed;
    long totalBytesSent;
    long totalBytesReceived;

    // CSV
    std::ofstream csvFile;
    std::string csvFilePath;

public:
    VeinsInetEVChargingApp();
    virtual ~VeinsInetEVChargingApp();

protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleStartOperation(inet::LifecycleOperation* op) override;
    virtual void handleMessageWhenUp(cMessage* msg) override;
    virtual void processPacket(std::shared_ptr<inet::Packet> pk) override;
    virtual void sendPacket(std::unique_ptr<inet::Packet> pk) override;

    // Attack
    void startAttack();
    void stopAttack();
    void sendAttackPacket();
    void sendToTarget(const char* mcastAddr, const char* prefix,
                      const char* commType, const char* destAddr);

    // Battery & Charging
    void updateBattery();
    void checkChargingNeed();
    void sendChargeRequest();
    void handleChargeResponse(const std::string& pktName);
    void beginCharging();
    void endCharging();
    void sendChargeComplete();

    // Normal traffic
    void sendNormalTraffic();

    // Utility
    void setSumoColor();
    double calculatePacketEnergy(int pktSize);
    inet::Coord getNodePosition(const char* nodeName);
    double getMySpeed();
    double distanceTo(const char* nodeName);

    // CSV
    void initCSV();
    void logCSV(const char* eventType, const char* commType, int pktSize,
                double iat, const char* srcAddr, const char* tgtAddr,
                int seqNum, const char* pktName);
    void closeCSV();
};

} // namespace veins

#endif
