# EV2X Cyberattack Attack Simulation Dataset

A network-level dataset for detecting **Denial-of-Service (DoS) attacks** in **Electric Vehicle (EV) communication networks**, generated using high-fidelity vehicular network simulation. The dataset captures Vehicle-to-Everything (V2X) communication traffic under normal and attack conditions across three distinct communication channels: **EV-to-EV**, **EV-to-Charging Station**, and **EV-to-RSU**.

## 1. Simulation Tools

This dataset was generated using a co-simulation framework that couples a vehicular network simulator with a microscopic traffic simulator, communicating via the Veins framework. All tools are open-source.

| Tool | Version | Role | Website |
|------|---------|------|---------|
| **OMNeT++** | 5.6.2 | Discrete Event Simulation engine | [omnetpp.org](https://omnetpp.org) |
| **INET Framework** | 4.2.5 | Network protocol models (TCP/IP, IEEE 802.11, IPv4, UDP) | [inet.omnetpp.org](https://inet.omnetpp.org) |
| **Veins** | 5.2 | Vehicular networking framework (OMNeT++ ↔ SUMO bridge) | [veins.car2x.org](https://veins.car2x.org) |
| **SUMO** | 1.12.0 | Microscopic traffic simulator (vehicle mobility) | [eclipse.dev/sumo](https://eclipse.dev/sumo) |
| **Python** | 3.10.4 | Data processing, EDA, and ML dataset preparation | [python.org](https://python.org) |

### Tool Descriptions

**OMNeT++ 5.6.2** is a modular, component-based C++ discrete event simulation framework widely used in academic research. It provides the core simulation kernel, module system, message passing, signal/statistic recording, and a graphical runtime environment (Qtenv). All simulation entities (EVs, Charging Stations, RSUs, radio medium) are implemented as OMNeT++ modules described in NED (Network Description) language and configured via `.ini` files.

**INET Framework 4.2.5** is the standard network simulation library for OMNeT++. It provides validated models for the full network stack including:
- **Physical layer**: `Ieee80211ScalarRadioMedium` — models radio signal propagation, path loss, interference, and reception on the 5.9 GHz DSRC band
- **Link layer**: IEEE 802.11p (WAVE) — the vehicular communication standard, operating in ad-hoc mode for direct V2X communication
- **Network layer**: IPv4 with multicast support for group-based communication
- **Transport layer**: UDP sockets for low-latency, connectionless packet delivery
- **Application layer**: `ApplicationPacket` with sequence numbers and configurable payload sizes
- **Node model**: `AdhocHost` — a complete network node with radio, MAC, IP, and application layers
- **Energy model**: `SimpleEpEnergyStorage` for tracking battery consumption during communication

**Veins 5.2** bridges OMNeT++ and SUMO in real-time using a TCP connection (TraCI protocol). It provides:
- `VeinsInetManager`: Manages the SUMO connection, dynamically creates and destroys vehicle modules in OMNeT++ as vehicles enter/leave the SUMO road network
- `VeinsInetApplicationBase`: Base class for vehicular network applications with built-in V2X communication support
- `VeinsInetMobility`: Synchronizes vehicle positions, speeds, and headings from SUMO into OMNeT++ every 100ms (configurable)
- Vehicle type mapping: SUMO vehicle types are mapped to OMNeT++ module types (e.g., `VeinsInetEVCar`)

**SUMO 1.12.0** (Simulation of Urban Mobility) is a microscopic, continuous road traffic simulator. It provides:
- Realistic vehicle movement: acceleration, deceleration, lane changes, and intersection behavior
- Route generation: vehicles follow defined routes or can be generated with random trips
- Real-time position and speed data exported to Veins at each simulation step (100ms interval)
- The SUMO scenario defines the road network topology, traffic demand, and vehicle types

---

## 2. Simulation Architecture

### How the Simulation Was Built in OMNeT++

The simulation follows a layered architecture combining all four tools:

```
┌─────────────────────────────────────────────────────────────┐
│                    OMNeT++ 5.6.2 (Core Engine)              │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              EVDoSScenario (Network)                  │   │
│  │                                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │  │  EV[0..1]   │  │   CS[0]     │  │   RSU[0]    │  │   │
│  │  │ (Dynamic)   │  │ (Static)    │  │ (Static)    │  │   │
│  │  │ DoSApp      │  │ ReceiverApp │  │ ReceiverApp │  │   │
│  │  │ 802.11p     │  │ 802.11p     │  │ 802.11p     │  │   │
│  │  │ IPv4/UDP    │  │ IPv4/UDP    │  │ IPv4/UDP    │  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │   │
│  │         │                │                │          │   │
│  │  ┌──────┴────────────────┴────────────────┴──────┐   │   │
│  │  │     Ieee80211ScalarRadioMedium (5.9 GHz)      │   │   │
│  │  └───────────────────────────────────────────────┘   │   │
│  │                                                      │   │
│  │  ┌──────────────────┐  ┌──────────────────────────┐  │   │
│  │  │ VeinsInetManager │  │ Ipv4NetworkConfigurator  │  │   │
│  │  │  (TraCI Bridge)  │  │  10.0.x.x/16 subnet     │  │   │
│  │  └────────┬─────────┘  └──────────────────────────┘  │   │
│  └───────────┼──────────────────────────────────────────┘   │
│              │ TCP (port 9999)                               │
│              ▼                                               │
│  ┌──────────────────┐                                       │
│  │  SUMO 1.12.0     │  ← Vehicle mobility (positions,      │
│  │  (Traffic Sim)   │     speeds, routes) updated every     │
│  │                  │     100ms via TraCI protocol           │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

## 2. Network Topology & Configuration

### Node Placement

| Node | Type | Position | Role |
|------|------|----------|------|
| `ev[0]` | Electric Vehicle | Dynamic (SUMO) | **Attacker** — sends DoS flood + BSM |
| `ev[1]` | Electric Vehicle | Dynamic (SUMO) | **Victim/Normal** — sends BSM only |
| `cs[0]` | Charging Station | Fixed (400, 500) | **Receiver** — logs EV2CS + BSM traffic |
| `rsu[0]` | Road-Side Unit | Fixed (600, 300, z=10m) | **Receiver** — logs EV2RSU + BSM traffic |

### Communication Parameters

| Parameter | Value |
|-----------|-------|
| Wireless standard | IEEE 802.11p (DSRC/WAVE) |
| Frequency | 5.9 GHz |
| Channel | 3 (CCH - Control Channel) |
| Data rate | 6 Mbps |
| EV transmit power | 100 mW (20 dBm) |
| RSU transmit power | 200 mW (23 dBm) |
| Receiver sensitivity | -89 dBm |
| Transport protocol | UDP (port 9001) |
| IP addressing | 10.0.x.x / 255.255.0.0 |
| Simulation duration | 100 seconds |

### Communication Ranges

| Range Type | Distance |
|------------|----------|
| EV-to-EV | 1500 m |
| EV-to-CS | 800 m |
| EV-to-RSU | 1500 m |

---
Ưitter**: ±30% randomization prevents perfectly periodic patterns, mimicking sophisticated attackers
- **Battery cost**: The attacker consumes real battery energy for each attack packet, modeled with physics-based energy calculation
- **Simultaneous normal traffic**: The attacker also sends legitimate BSM at 1–5 Hz during the attack, blending malicious and benign behavior

### Normal Traffic Model (Baseline)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Message type | BSM (Basic Safety Message) | SAE J2735 standard |
| Frequency | 1–5 Hz | Randomized interval (0.2–1.0s) |
| Packet size | 200–400 bytes | Realistic BSM payload |
| Multicast group | 224.0.0.1 | Broadcast to all V2X nodes |

---

## 3. How to Reproduce

### Prerequisites

| Software | Version | Download |
|----------|---------|----------|
| OMNeT++ | 5.6.2 | [omnetpp.org/download](https://omnetpp.org/download) |
| INET Framework | 4.2.5 | [github.com/inet-framework/inet](https://github.com/inet-framework/inet) |
| Veins | 5.2 | [veins.car2x.org/download](https://veins.car2x.org/download) |
| SUMO | 1.12.0 | [eclipse.dev/sumo](https://eclipse.dev/sumo) |
| Python | 3.10+ | [python.org](https://python.org) |

### Steps

1. **Install OMNeT++ 5.6.2** and configure the IDE
2. **Import INET 4.2.5** as a project in OMNeT++ IDE and build it
3. **Import Veins 5.2** as a project in OMNeT++ IDE and build it
4. **Import this project (evAttack)** as a project in OMNeT++ IDE
   - Set project references to both INET and Veins
   - Build the project (generates the shared library)
5. **Start SUMO** via Veins' `sumo-launchd.py`:
   ```bash
   python veins-5.2/sumo-launchd.py -vv -c sumo
   ```
6. **Run each scenario** from the OMNeT++ IDE:
   - Right-click `omnetpp.ini` → Run As → OMNeT++ Simulation
   - Select the desired configuration (EVtoEV_DoS, EVtoCS_DoS, EVtoRSU_DoS, or AllTypes_DoS)
   - Run the simulation (100s simulated time)
7. **Collect CSV outputs** from the `results/` directory
8. **Run the EDA notebook** (`EV_DoS_EDA.ipynb`) to process data and export ML-ready datasets:
   ```bash
   pip install pandas numpy matplotlib seaborn scipy scikit-learn
   jupyter notebook EV_DoS_EDA.ipynb
   ```

---

## 4. Citation

If you use this dataset in your research, please cite:

```bibtex
@dataset{ev_dos_attack_dataset,
  title     = {EV DoS Attack Simulation Dataset for V2X Intrusion Detection},
  year      = {2025},
  note      = {Generated using OMNeT++ 5.6.2, INET 4.2.5, Veins 5.2, and SUMO 1.12.0},
  keywords  = {DoS attack, electric vehicle, V2X, DSRC, intrusion detection, 
               network security, vehicular network, machine learning dataset}
}
```

---

## 5. License

This dataset is provided for research and educational purposes. Please refer to the individual licenses of the simulation tools used:
- OMNeT++: Academic Public License
- INET Framework: LGPL
- Veins: GPL v2
- SUMO: EPL v2

---

*Dataset generated and documented in 2026. For questions or issues, please open a GitHub issue.*