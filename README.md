# 🛡️ SecOps Core | Enterprise ITAM & Network Security Dashboard

![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**SecOps Core** is a lightweight, self-hosted IT Asset Management (ITAM) and active Intrusion Prevention System (IPS). It combines passive network telemetry, active Nmap fingerprinting, real-time vulnerability cross-referencing, and active containment into a single, interactive dashboard.

---

## ✨ Key Features

### 📡 Passive Telemetry & Fingerprinting
* **Silent Device Discovery:** Passively monitors DHCP, DNS, and mDNS traffic to catalog hidden devices (Smart TVs, IoT hardware, consoles) without triggering active alarms.
* **Deep-Dive Signatures:** Extracts DHCP Parameter Request Lists (PRL) and mDNS TXT records to accurately profile hardware.
* **Interactive Topology Map:** A physics-based network graph mapping your entire subnet ecosystem. Click any node to instantly view its diagnostics.

### ⚔️ Active Defense & Remediation (IPS)
* **ARP Quarantine:** Actively isolates rogue assets or infected nodes using localized ARP poisoning, effectively blackholing their network access instantly.
* **Wake-on-LAN (WoL):** Triggers Layer-3 UDP directed broadcasts to wake sleeping assets for patching or scanning.

### 🛡️ Threat Intelligence & Alerting
* **CISA KEV Correlation:** Actively cross-references open ports against the official CISA Known Exploited Vulnerabilities catalog.
* **Lateral Movement Detection:** Tracks TCP SYN requests and triggers alerts if a compromised node attempts rapid internal port scanning or network discovery.
* **Real-Time Webhooks:** Pushes critical alerts directly to Discord, Slack, or MS Teams.

---

## 🚀 What's New in v2.0.0 (Enterprise Update)

The v2.0.0 release transitions SecOps Core from a homelab utility to an enterprise-grade platform:

* **Prometheus Metrics Pipeline:** Exposes a standard `/metrics` endpoint for Grafana integration (`secops_devices_total`, `secops_vulnerable_total`, etc.).
* **SIEM Integration:** Native Syslog forwarding to stream network alerts directly to Splunk, Elastic, or Graylog.
* **Layer-2 Bandwidth Analytics:** A real-time "Top Talkers" widget tracking which devices are consuming the most local traffic (helpful for detecting data exfiltration).
* **Historical Trend Charting:** Interactive Chart.js graphs mapping infrastructure scale and vulnerability counts over the last 10 audits.
* **Dark Mode & UI Overhaul:** Dynamic theme toggling and a new dedicated Analytics tab.

---

## 🛠️ Architecture & Tech Stack

* **Backend:** Python 3.10, FastAPI, Scapy, python-nmap, SQLite3.
* **Frontend:** HTML5, CSS3, Vanilla JavaScript, Vis.js (Topology Graph), Chart.js.
* **Deployment:** Docker & Docker Compose (Host Network Mode).

---

## 📦 Deployment (Docker)

Because SecOps Core requires raw network socket access (for packet sniffing and ARP spoofing) and OS-level tools like Nmap, Docker is the required deployment method.

### 1. Clone the repository

git clone [https://github.com/YOUR_USERNAME/secops-core.git](https://github.com/YOUR_USERNAME/secops-core.git)
cd secops-core

### 2. Configure docker-compose.yml

Create or modify your docker-compose.yml file. Note: network_mode: "host" and elevated capabilities are mandatory.
YAML

version: '3.8'

services:
  secops-core:
    build: .
    container_name: secops-core
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - HOST=0.0.0.0
      - PORT=13000
      - TARGET_SUBNET=192.168.1.0/24
      - AUTOSCAN_INTERVAL=900
      # Optional Integrations:
      # - WEBHOOK_URL=[https://discord.com/api/webhooks/](https://discord.com/api/webhooks/)...
      # - SYSLOG_SERVER=192.168.1.100:514
      - DB_PATH=/app/data/network_state.db
    volumes:
      - ./data:/app/data

### 3. Deploy the Stack

docker-compose up -d --build

### 4. Access the Dashboard

Open your browser and navigate to http://localhost:13000.
⚙️ Environment Variables
Variable	Default	Description
HOST	0.0.0.0	The interface IP the web server binds to.
PORT	13000	The port the web dashboard is served on.
TARGET_SUBNET	192.168.1.0/24	The CIDR block you wish to actively audit via Nmap.
AUTOSCAN_INTERVAL	900	Automated Nmap scan schedule in seconds. Set to 0 for manual only.
NET_INTERFACE	Auto-detected	Force Scapy to bind to a specific physical interface (e.g., eth0).
WEBHOOK_URL	None	Slack/Discord Webhook URL for push notifications.
SYSLOG_SERVER	None	IP:PORT of your SIEM for log forwarding (e.g., 10.0.0.5:514).

⚠️ Disclaimer & Ethical Use

This tool includes active network disruption capabilities.
The "Toggle Isolation" feature executes an automated, localized Denial of Service attack (ARP Poisoning) against target MAC addresses.

    Do NOT run this software on corporate, public, or educational networks without explicit written authorization from the network owner or administration.

    This software is provided for educational, homelab, and authorized defensive operations only.

    The authors and contributors are not responsible for network outages, data loss, or damages caused by the misuse of this tool.

🤝 Contributing

Pull requests are welcome! If you are planning to add major features, please open an issue first to discuss what you would like to change.
📄 License

This project is licensed under the MIT License.
