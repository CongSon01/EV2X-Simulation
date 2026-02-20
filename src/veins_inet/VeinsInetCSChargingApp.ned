// CS app with charging protocol (request/response) and DoS packet logging

package evattack.veins_inet;

simple VeinsInetCSChargingApp like inet.applications.contract.IApp
{
    parameters:
        @class(veins::VeinsInetCSChargingApp);
        @display("i=block/plug");

        // CS capacity: how many EVs can charge at once
        int maxSlots = default(1);

        // CS battery model
        double csBatteryCapacity @unit(Wh) = default(50000Wh);  // 50 kWh
        double initialCSSoC = default(1.0);                      // start full
        double chargingPowerW @unit(W) = default(7200W);         // W per EV
        double gridRechargePowerW @unit(W) = default(10000W);    // W from grid

        // Rate limiting: max packets received per second (0=unlimited)
        int maxPktPerSecond = default(0);

        string interfaceTableModule;

        // Signals
        @signal[packetReceived](type=long);
        @signal[packetSize](type=long);
        @signal[interArrivalTime](type=double);
        @signal[energyConsumption](type=double);
        @signal[txDuration](type=double);
        @signal[chargeRequestReceived](type=long);
        @signal[slotsInUse](type=long);

        @statistic[packetReceived](record=count,vector);
        @statistic[packetSize](record=histogram,vector);
        @statistic[interArrivalTime](record=histogram,vector);
        @statistic[energyConsumption](record=vector,stats);
        @statistic[txDuration](record=vector,stats);
        @statistic[chargeRequestReceived](record=count,vector);
        @statistic[slotsInUse](record=vector);

    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
