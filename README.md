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
```bash
git clone [https://github.com/YOUR_USERNAME/secops-core.git](https://github.com/YOUR_USERNAME/secops-core.git)
cd secops-core
