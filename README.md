# 🛡️ SecOps Core

An enterprise-grade, multi-protocol network asset discovery and vulnerability management engine. Built with Python and FastAPI, featuring a zero-latency UI for real-time network topology tracking.

## ✨ Features
* **Multi-Protocol Discovery:** Utilizes ARP sweeps, ICMP pings, and SSDP multicast probes to wake up deep-sleep IoT devices, Smart TVs, and mobile endpoints.
* **3-Tier Asset Identity:** Scrapes internal HTTP `<title>` tags, mDNS `TXT` payloads, and DHCP/NetBIOS hostnames to accurately identify hardware.
* **Nmap Deep Fingerprinting:** Asynchronous, background OS and service fingerprinting without blocking the UI.
* **CISA KEV Integration:** Automatically cross-references discovered open ports against the official US Government Known Exploited Vulnerabilities ledger.
* **Container Ready:** Dynamic environment variable detection natively supports Docker and Kubernetes deployments.

## ⚙️ Prerequisites
Because this tool performs raw packet manipulation and deep network interrogation, specific system prerequisites are required:

1. **Python 3.9+**
2. **Nmap Binary:** The host machine must have [Nmap](https://nmap.org/download.html) installed and added to the system PATH.
3. **Execution Privileges:** * **Windows:** Must be run as Administrator. You must also install [Npcap](https://npcap.com/) (installed with Wireshark/Nmap).
    * **Linux/macOS:** Must be run with `sudo` (requires `root` or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities).

## 🚀 Quick Start

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/secops-core.git](https://github.com/YOUR_USERNAME/secops-core.git)
   cd secops-core
