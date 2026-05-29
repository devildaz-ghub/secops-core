# 🛡️ SecOps Core | Enterprise ITAM

SecOps Core (v2.0.0) is a lightweight, high-performance Enterprise IT Asset Management (ITAM) and Network Telemetry platform. It combines active vulnerability scanning with passive network sniffing to provide real-time visibility into your infrastructure, identify rogue devices, and execute active remediation steps.

## ✨ Features

* **Interactive Network Topology:** Visualize your entire network map in real-time using a physics-based, interactive graph.
* **Passive Telemetry & Sniffing:** Passively intercepts DHCP, mDNS, and DNS traffic to identify devices without noisy active scans.
* **Active Vulnerability Scanning:** Integrates with Nmap and the official CISA Known Exploited Vulnerabilities (KEV) catalog to detect critical open ports and software threats.
* **Advanced Threat Detection:** Automatically flags rogue devices, port scanning, and lateral movement attempts.
* **Active Remediation:** * **ARP Quarantine:** Isolate compromised or rogue nodes immediately using targeted ARP poisoning.
  * **Wake-on-LAN (WoL):** Wake dormant machines directly from the dashboard.
* **Enterprise SIEM Integration:** Forwards critical network alerts to standard Syslog servers for enterprise monitoring.

## 🛠️ Tech Stack

* **Backend:** Python 3.x, FastAPI, Uvicorn, Scapy, Python-Nmap, SQLite3.
* **Frontend:** Vanilla HTML/JS/CSS, Vis-Network (Topology), Chart.js (Analytics).
* **Databases:** Local SQLite for state management, dynamic sync with external CISA KEV and MacVendor APIs.

## 🚀 Installation & Setup

### Prerequisites

Ensure you have the following installed on your system:
* Python 3.8+
* Nmap (must be accessible in your system's PATH)
* Root/Administrator privileges (required for raw packet sniffing and ARP spoofing)

### Quick Start

1. **Clone the repository**
2. Install Python Dependencies
           pip install fastapi uvicorn scapy python-nmap pydantic mac-vendor-lookup
3. Configure Environment Variables (Optional)
You can customize the runtime environment by exporting these variables before starting the server:
  ```
            PORT: The port the web UI will run on (Default: 13000)
            HOST: The bind address (Default: 0.0.0.0)
            TARGET_SUBNET: The default CIDR block to scan (Default: 192.168.1.0/24)
            SYSLOG_SERVER: IP and port for SIEM forwarding (e.g., 192.168.1.100:514)
            NET_INTERFACE: Specific network interface to bind to (Default: Auto-detect)
   ```
4. Run the Server
            Execute the backend application. Note: Root privileges are required.
        ``` sudo python3 server.py ```
5. Access the Dashboard
            Open your web browser and navigate to:
       ```  http://localhost:13000 ```

 ##  📡 API Endpoints
SecOps Core runs a fully documented REST API backend. Core endpoints include:
```
GET /api/devices - Retrieve the latest matrix of known devices.

GET /api/topology - Fetch the node/edge graph data for visualization.

GET /metrics - Prometheus-compatible endpoint for infrastructure metrics.

GET /api/trends - Historical asset and vulnerability counts.

POST /api/device/{mac}/quarantine - Toggle ARP isolation for a specific MAC address.

POST /api/device/{mac}/wake - Send a Magic Packet to wake a specific device.
```
## 📂 Project Structure
server.py - The core FastAPI backend application handling routing, background tasks, and active/passive scanning engines.

index.html - The single-page frontend application dashboard providing the interactive matrix, topology map, and analytics.

network_state.db - Auto-generated SQLite database for persistence.

## ⚠️ Security Warning
Use Responsibly: This tool includes active exploitation mitigation features like ARP poisoning. It is designed strictly for authorized auditing and defensive operations within networks you own or have explicit permission to monitor. Unauthorized use on third-party networks is illegal.
