package evattack.veins_inet;

import evattack.veins_inet.VeinsInetApplicationBase;

simple VeinsInetDoSApplication extends VeinsInetApplicationBase
{
    parameters:
        @class(veins::VeinsInetDoSApplication);
        @display("i=block/app");
        
        // DoS Attack Parameters
        bool isAttacker = default(false);
        double attackInterval @unit(s) = default(0.1s);
        int attackPacketSize @unit(B) = default(1024B);
        double attackStartTime @unit(s) = default(10s);
        double attackDuration @unit(s) = default(30s);
}