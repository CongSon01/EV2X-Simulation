// EV app with real-time SoC, charging protocol, and DoS attack

package evattack.veins_inet;

import evattack.veins_inet.VeinsInetApplicationBase;

simple VeinsInetEVChargingApp extends VeinsInetApplicationBase
{
    parameters:
        @class(veins::VeinsInetEVChargingApp);

        // --- Attack parameters ---
        bool isAttacker = default(false);
        string targetType = default("EV");        // EV, CS, RSU
        string targetAddress = default("");
        double attackStartTime @unit(s) = default(10s);
        double attackDuration @unit(s) = default(60s);
        double packetInterval @unit(s) = default(0.01s);
        int packetSize @unit(B) = default(1024B);

        // --- Battery parameters (condensed for quick simulation) ---
        // 200 Wh = tiny battery so SoC changes are visible in <5 min run
        double batteryCapacity @unit(Wh) = default(200Wh);
        double initialSoC = default(0.8);           // 0.0-1.0
        double energyPerMeter @unit(Wh) = default(0.05Wh); // 50 Wh/km
        double chargingPowerW @unit(W) = default(7200W);    // 7.2 kW Level-2
        double socThreshold = default(0.2);               // seek charging below 20%
        double chargingRange @unit(m) = default(300m);       // wireless range: EV sends ChargeReq within this distance
        double physicalChargingRange @unit(m) = default(15m);  // physical plug-in: must be this close to start charging
        string csEdgeId = default("B1B2");                     // SUMO edge at the CS (used for rerouting)

        // --- Display ---
        string sumoColor = default("yellow"); // "red" for attacker, "yellow" for normal

        // --- Communication ranges ---
        double ev2evRange @unit(m) = default(500m);
        double ev2csRange @unit(m) = default(500m);
        double ev2rsuRange @unit(m) = default(500m);

        // --- Route continuation after charging ---
        // Space-separated SUMO edge IDs to visit in order after charging ends.
        // Prevents vehicle from disappearing when CS edge becomes its terminal.
        string destinations = default("");  // e.g. "C2C1 A0B0 C0B0"

        // --- Rate limiting ---
        // Max packets received per second. 0 = unlimited.
        int maxPktPerSecond = default(0);

        // --- Signals ---
        @signal[packetSent](type=long);
        @signal[packetReceived](type=long);
        @signal[packetSize](type=long);
        @signal[interArrivalTime](type=double);
        @signal[batteryLevel](type=double);
        @signal[soc](type=double);
        @signal[energyConsumption](type=double);
        @signal[isCharging](type=bool);
        @signal[senderSpeed](type=double);
        @signal[txDuration](type=double);

        @statistic[packetSize](record=vector,stats);
        @statistic[interArrivalTime](record=vector,stats);
        @statistic[batteryLevel](record=vector,stats);
        @statistic[soc](title="State of Charge"; record=vector,stats);
        @statistic[energyConsumption](record=vector,stats);
        @statistic[isCharging](record=vector);
        @statistic[senderSpeed](record=vector,stats);
        @statistic[txDuration](record=vector,stats);
}
