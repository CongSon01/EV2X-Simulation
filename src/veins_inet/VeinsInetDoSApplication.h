#ifndef VEINSINET_DOSAPPLICATION_H
#define VEINSINET_DOSAPPLICATION_H

#include "veins_inet/VeinsInetApplicationBase.h"
#include "veins_inet/VeinsInetSampleMessage_m.h"
#include <vector>
#include <deque>
#include <fstream>

namespace veins {

class VeinsInetDoSApplication : public VeinsInetApplicationBase {
protected:
    // Parameters
    bool isAttacker;
    simtime_t attackInterval;
    int attackPacketSize;
    simtime_t attackStartTime;
    simtime_t attackDuration;

    // Self messages
    cMessage* attackTimer;

    // Basic counters
    long totalPacketsSent;
    long totalPacketsReceived;
    long totalBytesSent;
    long totalBytesReceived;
    
    // Advanced metrics tracking
    std::deque<simtime_t> packetArrivalTimes;  // For IAT calculation
    std::vector<int> receivedPacketSizes;
    simtime_t lastPacketTime;
    simtime_t firstPacketTime;
    
    // Statistical accumulators
    double sumInterArrivalTime;
    double sumSquaredInterArrivalTime;
    int iatCount;
    
    // Output vectors
    cOutVector packetsSentVector;
    cOutVector packetsReceivedVector;
    cOutVector bytesReceivedVector;
    cOutVector interArrivalTimeVector;
    cOutVector packetSizeVector;
    
    // CSV logging for packet-level data
    static std::ofstream packetLog;
    static bool csvHeaderWritten;

protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    
    virtual void handleMessageWhenUp(cMessage* msg) override;
    virtual void processPacket(std::shared_ptr<inet::Packet> pk) override;
    virtual void finish() override;

    // DoS attack method
    virtual void sendDoSPacket();
    
    // Log packet details to CSV
    virtual void logPacketToCSV(const char* senderName, int senderNodeId, int receiverNodeId,
                                int packetSize, double iat, const char* packetType, bool isAttack);

public:
    VeinsInetDoSApplication();
    virtual ~VeinsInetDoSApplication();
};

} // namespace veins

#endif