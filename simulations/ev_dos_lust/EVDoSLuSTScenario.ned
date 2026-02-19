// LuST-based EV DoS attack scenario network
// Uses Luxembourg map with dynamic EVs + CS + RSU in IEEE 802.11p ad-hoc network
// Based on VeReMi paper configuration, adapted for EVs

package evattack.simulations.ev_dos_lust;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import evattack.veins_inet.VeinsInetManager;

network EVDoSLuSTScenario
{
    parameters:
        // CS and RSU counts - placed at key LuST intersections
        int numCS = default(3);
        int numRSUs = default(5);

        // Playground matches LuST network boundary
        // LuST convBoundary: approx 0,0 to 13640,11500
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

        // Charging stations at strategic positions within ROI
        cs[numCS]: AdhocHost {
            @display("i=block/control");
            numWlanInterfaces = 1;
            wlan[*].radio.displayCommunicationRange = false;
        }

        // RSUs at major intersections within ROI
        rsu[numRSUs]: AdhocHost {
            @display("i=device/antennatower");
            numWlanInterfaces = 1;
            wlan[*].radio.displayCommunicationRange = false;
        }
}
