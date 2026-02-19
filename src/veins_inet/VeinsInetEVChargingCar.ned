// EV Car with charging capability (used in controlled scenario)
package evattack.veins_inet;

import inet.node.inet.AdhocHost;

module VeinsInetEVChargingCar extends AdhocHost
{
    parameters:
        @display("i=block/wtx");
        numApps = 1;
        app[0].typename = default("VeinsInetEVChargingApp");
        mobility.typename = default("VeinsInetMobility");
        numWlanInterfaces = 1;
        wlan[0].typename = default("Ieee80211Interface");
        wlan[0].radio.typename = default("Ieee80211ScalarRadio");
}
