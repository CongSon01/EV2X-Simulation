// Base application layer for Veins-INET integration

package evattack.veins_inet;

import inet.applications.contract.IApp;

simple VeinsInetApplicationBase like IApp
{
    parameters:
        string interfaceTableModule;
        string interface = default("wlan0");

        @display("i=block/app");
        @class(veins::VeinsInetApplicationBase);
        @signal[packetSent](type=long);
        @signal[packetReceived](type=long);
        @statistic[packetReceived](title="packets received"; source=packetReceived; record=count,sum,vector; interpolationmode=none);
        @statistic[packetSent](title="packets sent"; source=packetSent; record=count,sum,vector; interpolationmode=none);
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
