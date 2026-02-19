package evattack.simulations.dos_attack;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.contract.IIntegratedVisualizer;

import evattack.veins_inet.VeinsInetManager;

network DoSScenario
{
    parameters:
        @display("bgb=1000,1000");
        
    submodules:
        visualizer: <default("IntegratedCanvasVisualizer")> like IIntegratedVisualizer if hasVisualizer() {
            @display("p=50,50");
        }
        
        configurator: Ipv4NetworkConfigurator {
            @display("p=50,150");
        }
        
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=50,250");
        }
        
        manager: VeinsInetManager {
            @display("p=50,350");
        }
        
    connections allowunconnected:
}