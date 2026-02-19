// EV Car module with manual battery tracking
package evattack.veins_inet;

import inet.node.inet.AdhocHost;

module VeinsInetEVCar extends AdhocHost
{
    parameters:
        @display("i=block/wtx");
        
        // Application
        numApps = 1;
        app[0].typename = default("VeinsInetEVDoSApplication");
        
        // Mobility
        mobility.typename = default("VeinsInetMobility");
        
        // WLAN interface
        numWlanInterfaces = 1;
        wlan[0].typename = default("Ieee80211Interface");
        wlan[0].radio.typename = default("Ieee80211ScalarRadio");
}
