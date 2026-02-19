// EV DoS Attack application with battery management and multicast targeting

#ifndef __VEINS_INET_EVDOSAPPLICATION_H_
#define __VEINS_INET_EVDOSAPPLICATION_H_

#include "veins_inet/VeinsInetApplicationBase.h"
#include "inet/power/storage/SimpleEpEnergyStorage.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/common/geometry/common/Coord.h"
#include <fstream>

using namespace omnetpp;
using namespace inet;

namespace veins {

class VEINS_INET_API VeinsInetEVDoSApplication : public VeinsInetApplicationBase
{
protected:
    bool isAttacker;
    std::string targetType;
    std::string targetAddress;
    simtime_t attackStartTime;
    simtime_t attackDuration;
    simtime_t packetInterval;
    int packetSize;
    
    double batteryCapacity;
    double currentBatteryLevel;
    double chargingPower;
    double chargingThreshold;
    bool isCharging;
    
    double ev2evRange;
    double ev2csRange;
    double ev2rsuRange;
    
    cMessage* attackTimer;
    cMessage* packetTimer;
    cMessage* chargingTimer;
    cMessage* normalTrafficTimer;  // Timer for normal V2X background traffic
    
    simsignal_t packetSentSignal;
    simsignal_t packetReceivedSignal;
    simsignal_t packetSizeSignal;
    simsignal_t interArrivalTimeSignal;
    simsignal_t batteryLevelSignal;
    simsignal_t energyConsumptionSignal;
    simsignal_t communicationTypeSignal;
    simsignal_t isChargingSignal;
    simsignal_t senderSpeedSignal;
    simsignal_t txDurationSignal;
    
    simtime_t lastPacketTime;
    int packetsSent;
    int packetsReceived;
    double totalEnergyConsumed;
    
    simtime_t lastSentTimestamp;  // Track last normal packet sent time
    
    // Stats tracking for .sca scalar output
    long totalBytesSent;
    long totalBytesReceived;
    int minSentPktSize;
    int maxSentPktSize;
    double sumIAT;      // Sum of inter-arrival times
    double sumIATSq;    // Sum of IAT squared (for std)
    int iatCount;       // Number of IAT samples
    
    std::ofstream csvFile;
    std::string csvFilePath;
    
    power::SimpleEpEnergyStorage* energyStorage;

public:
    VeinsInetEVDoSApplication();
    virtual ~VeinsInetEVDoSApplication();

protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleStartOperation(inet::LifecycleOperation* operation) override;
    virtual void handleMessageWhenUp(cMessage* msg) override;
    
    virtual void processPacket(std::shared_ptr<inet::Packet> pk) override;
    
    virtual void startAttack();
    virtual void stopAttack();
    virtual void sendAttackPacket();
    
    virtual void sendToEV(const char* destAddr);
    virtual void sendToCS(const char* destAddr);
    virtual void sendToRSU(const char* destAddr);
    virtual void sendMixedAttack();
    virtual void sendToTarget(const char* mcastAddr, const char* prefix, 
                             const char* commType, const char* destAddr);
    
    virtual void sendNormalTraffic();
    
    virtual void sendPacket(std::unique_ptr<inet::Packet> pk) override;
    
    virtual void updateBatteryLevel();
    virtual void checkChargingNeed();
    virtual void startCharging();
    virtual void stopCharging();
    virtual double calculatePacketEnergy(int pktSize);
    
    virtual bool isInRange(inet::Coord targetPos, double range);
    virtual inet::Coord getNodePosition(const char* nodeName);
    virtual double getMySpeed();
    virtual std::string determineCommType(const char* destAddr);
    
    virtual void initializeCSVLogging();
    virtual void logPacketToCSV(const char* eventType, const char* commType, 
                                int pktSize, double iat, double battery, 
                                double energy, const char* srcAddress,
                                const char* targetAddress,
                                int seqNum, const char* pktName);
    virtual void closeCSVLogging();
};

} // namespace veins

#endif
