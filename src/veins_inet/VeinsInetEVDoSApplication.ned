// EV DoS Attack application with battery management

package evattack.veins_inet;

import evattack.veins_inet.VeinsInetApplicationBase;

simple VeinsInetEVDoSApplication extends VeinsInetApplicationBase
{
    parameters:
        @class(veins::VeinsInetEVDoSApplication);
        
        bool isAttacker = default(false);
        string targetType = default("EV");
        string targetAddress = default("");
        double attackStartTime @unit(s) = default(10s);
        double attackDuration @unit(s) = default(30s);
        double packetInterval @unit(s) = default(0.1s);
        int packetSize @unit(B) = default(512B);
        
        double batteryCapacity @unit(Wh) = default(200Wh);
        double initialBatteryLevel @unit(Wh) = default(200Wh);
        double chargingPower @unit(W) = default(50W);
        double chargingThreshold @unit(Wh) = default(50Wh);
        
        double ev2evRange @unit(m) = default(1500m); 
        double ev2csRange @unit(m) = default(800m);
        double ev2rsuRange @unit(m) = default(1500m);
        
        @signal[packetSize](type=long);
        @signal[interArrivalTime](type=double);
        @signal[batteryLevel](type=double);
        @signal[energyConsumption](type=double);
        @signal[communicationType](type=string);
        @signal[isCharging](type=bool);
        
        @statistic[packetSize](record=vector,stats);
        @statistic[interArrivalTime](record=vector,stats);
        @statistic[batteryLevel](record=vector,stats);
        @statistic[energyConsumption](record=vector,stats);
        @statistic[communicationType](record=count);
        @statistic[isCharging](record=vector);
        
        @signal[senderSpeed](type=double);
        @signal[txDuration](type=double);
        @statistic[senderSpeed](title="node speed"; unit=mps; record=vector,stats; interpolationmode=none);
        @statistic[txDuration](title="tx duration estimate"; unit=s; record=vector,stats; interpolationmode=none);
}
