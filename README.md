# 🛡️ SecOps Core | ITAM & Network Security Dashboard

SecOps Core is a lightweight, self-hosted IT Asset Management (ITAM) and Intrusion Prevention System (IPS). It combines passive network telemetry, active Nmap fingerprinting, and real-time vulnerability cross-referencing into a single, interactive dashboard.

## ✨ Features

* **Passive Network Sniffing:** Silently monitors DHCP and mDNS traffic to catalog hidden devices (Smart TVs, IoT hardware, consoles) without triggering active alarms.
* **Interactive Topology Map:** A physics-based network graph mapping your entire subnet ecosystem.
* **Active Vulnerability Auditing:** Cross-references open ports against the official CISA Known Exploited Vulnerabilities (KEV) catalog.
* **Intrusion Prevention (ARP Quarantine):** Actively isolates rogue assets using localized ARP poisoning.
* **Webhooks:** Pushes real-time alerts to Discord/Slack when unauthorized devices connect to the network.

## 🚀 Deployment (Docker)

Because SecOps Core requires raw network socket access (for packet sniffing and ARP spoofing) and OS-level tools like Nmap, Docker is the recommended deployment method.

1. **Clone the repository:**
   
   git clone [https://github.com/YOUR_USERNAME/secops-core.git](https://github.com/YOUR_USERNAME/secops-core.git)
   cd secops-core

2. Configure your Subnet:
    Open docker-compose.yml and update the TARGET_SUBNET environment variable to match your local network (e.g., 192.168.1.0/24).

3. Deploy the stack:

   docker-compose up -d --build

4. Access the Dashboard:
    Open your browser and navigate to http://localhost:13000.

⚠️ Disclaimer & Ethical Use

This tool includes active network disruption capabilities (ARP Poisoning).
The "Toggle Isolation" feature executes a localized Denial of Service attack against the target MAC address.

    Do NOT run this software on corporate, public, or educational networks without explicit written authorization from the network owner.

    This software is provided for educational, homelab, and authorized defensive operations only. The authors are not responsible for network outages or damages caused by misuse.

🛠️ Tech Stack

    Backend: Python 3.10, FastAPI, Scapy, python-nmap, SQLite

    Frontend: HTML5, CSS3, Vanilla JavaScript, Vis.js (Topology Graph)