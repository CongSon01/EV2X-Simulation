package evattack.veins_inet;

import inet.node.inet.AdhocHost;

// Attacker car with DoS application
module VeinsInetAttackerCar extends AdhocHost
{
    parameters:
        @display("i=block/transport,red;is=vs");
        
        // Force DoS application
        numApps = 1;
        app[0].typename = "VeinsInetDoSApplication";
        app[0].isAttacker = true;
        app[0].attackInterval = 0.05s;
        app[0].attackPacketSize = 512B;
        app[0].attackStartTime = 10s;
        app[0].attackDuration = 40s;
        
        wlan[*].radio.typename = default("Ieee80211Radio");
        wlan[*].radio.channelNumber = 0;
        
        mobility.typename = default("VeinsInetMobility");
}