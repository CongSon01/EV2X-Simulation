// Toy scenario: 2 EVs, 1 CS, 1 RSU on a small 3x3 grid (400m x 400m)
// Easy to visualize EV-CS-RSU interactions at close range

package evattack.simulations.ev_dos_lust;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import evattack.veins_inet.VeinsInetManager;

network ToyEVDoSScenario
{
    parameters:
        int numCS = default(1);
        int numRSUs = default(1);

        // Small 3x3 grid: 400m x 400m + margin
        @display("bgb=500,500;bgg=100,1,grey95");

    submodules:
        visualizer: IntegratedCanvasVisualizer {
            @display("p=50,50");
        }

        configurator: Ipv4NetworkConfigurator {
            @display("p=50,100");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=50,150");
        }

        veinsManager: VeinsInetManager {
            @display("p=50,200");
        }

        // CS at grid center B1 (200,200) - charging station icon
        cs[numCS]: AdhocHost {
            @display("i=misc/chargingstation;is=l");
            numWlanInterfaces = 1;
        }

        // RSU between B1 and B2 (200,300) - antenna tower icon
        rsu[numRSUs]: AdhocHost {
            @display("i=device/antennatower;is=l");
            numWlanInterfaces = 1;
        }
}
