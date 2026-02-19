package evattack.veins_inet;

import inet.node.inet.AdhocHost;

// Vehicle module for V2V DoS simulation
// Application type set by omnetpp.ini
module VeinsInetCar extends AdhocHost
{
    parameters:
        @display("i=block/transport;is=s");
        
        wlan[*].radio.typename = default("Ieee80211Radio");
        wlan[*].radio.channelNumber = 0;
        
        mobility.typename = default("VeinsInetMobility");
}