// Controlled scenario: 2 EVs, 1 CS, 1 RSU on LuST map
// Scaled-down for dataset validation and attack impact analysis

package evattack.simulations.ev_dos_lust;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import evattack.veins_inet.VeinsInetManager;

network ControlledEVDoSScenario
{
    parameters:
        int numCS = default(1);
        int numRSUs = default(1);

        // LuST map boundary
        @display("bgb=13640,11500;bgg=500,1,grey95");

    submodules:
        visualizer: IntegratedCanvasVisualizer {
            @display("p=100,100");
        }

        configurator: Ipv4NetworkConfigurator {
            @display("p=100,200");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,300");
        }

        veinsManager: VeinsInetManager {
            @display("p=100,400");
        }

        // 1 Charging Station - INET chargingstation icon
        cs[numCS]: AdhocHost {
            @display("i=misc/chargingstation;is=l");
            numWlanInterfaces = 1;
            wlan[*].radio.displayCommunicationRange = false;
        }

        // 1 RSU - antenna tower icon
        rsu[numRSUs]: AdhocHost {
            @display("i=device/antennatower;is=l");
            numWlanInterfaces = 1;
            wlan[*].radio.displayCommunicationRange = false;
        }
}
