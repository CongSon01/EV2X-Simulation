// Simple receiver for CS (Charging Station) and RSU nodes

package evattack.veins_inet;

simple VeinsInetReceiverApp like inet.applications.contract.IApp
{
    parameters:
        @class(veins::VeinsInetReceiverApp);
        @display("i=block/app");
        
        @signal[packetReceived](type=long);
        @signal[packetSize](type=long);
        @signal[interArrivalTime](type=double);
        
        @statistic[packetReceived](title="packets received"; record=count,sum,vector; interpolationmode=none);
        @statistic[packetSize](title="packet size"; unit=B; record=histogram,vector; interpolationmode=none);
        @statistic[interArrivalTime](title="inter arrival time"; unit=s; record=histogram,vector; interpolationmode=none);
        
        @signal[energyConsumption](type=double);
        @signal[txDuration](type=double);
        @statistic[energyConsumption](title="energy consumption"; unit=J; record=vector,stats; interpolationmode=none);
        @statistic[txDuration](title="tx duration estimate"; unit=s; record=vector,stats; interpolationmode=none);
        
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
