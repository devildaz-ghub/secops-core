import os
import sys
import asyncio
import time
import re
import socket
from datetime import datetime
from mac_vendor_lookup import AsyncMacLookup
from fastapi.responses import FileResponse
from fastapi import FastAPI, Query, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import scapy.all as scapy
import nmap
import sqlite3
import json
import urllib.request
from contextlib import asynccontextmanager, closing
from typing import List, Optional

# =====================================================================
# 1. DYNAMIC ENVIRONMENT VARIABLE CONFIGURATION & ENVIRONMENT DETECTION
# =====================================================================
IS_WINDOWS = os.name == 'nt'
IS_CONTAINER = os.path.exists('/.dockerenv') or os.environ.get('KUBERNETES_SERVICE_HOST') is not None

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "13000"))
TARGET_SUBNET = os.getenv("TARGET_SUBNET", "192.168.1.0/24")
AUTOSCAN_INTERVAL = int(os.getenv("AUTOSCAN_INTERVAL", "900")) 
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "") # Add your Discord/Slack Webhook URL here

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.getenv("DB_PATH", os.path.join(BASE_DIR, "network_state.db"))
UI_FILE = os.getenv("UI_STATIC_PATH", os.path.join(BASE_DIR, "index.html"))

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TARGET_PORTS = [22, 23, 80, 443, 515, 554, 445, 8000, 8009, 8080, 9100, 9304, 32400, 62078]

# =====================================================================
# 2. CROSS-PLATFORM PRIVILEGE & RESOURCE RUNTIME VALIDATION
# =====================================================================
def verify_runtime_privileges():
    print(f"⚙️ Runtime Environment: {'Container (Docker/K8s)' if IS_CONTAINER else 'Native Host'}")
    if IS_WINDOWS:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            print("\n❌ CRITICAL: Administrator Privileges Required on Windows.")
            print("Launch your terminal using 'Run as Administrator'.\n")
            sys.exit(1)
    else:
        if os.getuid() != 0:
            if IS_CONTAINER:
                print("\n⚠️ WARNING: Running as non-root inside a container context.")
            else:
                print("\n❌ CRITICAL: Root privileges required on Linux. Use 'sudo'.\n")
                sys.exit(1)

verify_runtime_privileges()

ENV_INTERFACE = os.getenv("NET_INTERFACE")
if ENV_INTERFACE:
    TARGET_INTERFACE = ENV_INTERFACE
else:
    try:
        interfaces = scapy.conf.ifaces.keys()
        qnap_iface = next((i for i in interfaces if i.startswith("qvs") or i.startswith("br")), None)
        TARGET_INTERFACE = qnap_iface if qnap_iface else scapy.conf.iface
    except Exception:
        TARGET_INTERFACE = scapy.conf.iface

# =====================================================================
# 3. CORE STATE ENGINE & TELEMETRY
# =====================================================================
last_scan_time = time.time()
last_purge_time = time.time()

mac_checker = AsyncMacLookup()
LOCAL_KEV_CACHE = []
FINGERBANK_CACHE = {}
DEVICE_TELEMETRY = {}
NMAP_CACHE = {}
ALERTED_MACS = set() 
ACTIVE_QUARANTINES = set() 
sniffer_handle = None

SYSTEM_STATE = {"sniffer_paused": False, "intel_sync_complete": False}

LOCAL_OUI_FALLBACK = {
    "24:0A:C4": "Espressif Inc.", "30:AE:A4": "Espressif Inc.", "54:5A:A6": "Espressif Inc.", 
    "10:5A:17": "Tuya Smart", "2C:3A:E8": "Tuya Smart", "50:8A:06": "Tuya Smart",
    "28:CD:C1": "Raspberry Pi Ltd", "B8:27:EB": "Raspberry Pi Foundation", 
    "00:05:69": "VMware Inc.", "00:0C:29": "VMware Inc.", "52:54:00": "QEMU/KVM Virtual NIC"
}

def trigger_webhook(title: str, message: str, color: int = 16711680):
    if not WEBHOOK_URL: return
    try:
        payload = {"embeds": [{"title": title, "description": message, "color": color}]}
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=3)
    except Exception as e: print(f"[⚠️ WEBHOOK] Failed to send: {e}")

async def background_nmap_sync():
    global NMAP_CACHE, TARGET_SUBNET
    while True:
        if SYSTEM_STATE["intel_sync_complete"]:
            def run_nmap():
                nm = nmap.PortScanner()
                nm.scan(hosts=TARGET_SUBNET, arguments='-O -sV -F -T4 --host-timeout 30s')
                return nm
            try:
                nm_results = await asyncio.to_thread(run_nmap)
                for ip in nm_results.all_hosts():
                    host_data = nm_results[ip]
                    hostnames = [h['name'] for h in host_data.get('hostnames', []) if h['name']]
                    best_name = hostnames[0] if hostnames else ""
                    os_match = host_data['osmatch'][0]['name'] if 'osmatch' in host_data and len(host_data['osmatch']) > 0 else ""
                    NMAP_CACHE[ip] = {"nmap_name": best_name, "os": os_match, "vendor_dict": host_data.get('vendor', {})}
            except Exception: pass
        await asyncio.sleep(14400) 

async def background_intel_sync():
    global LOCAL_KEV_CACHE
    try: await mac_checker.update_vendors()
    except Exception: pass
    def fetch_cisa():
        req = urllib.request.Request(CISA_KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response: return json.loads(response.read().decode()).get("vulnerabilities", [])
    try: LOCAL_KEV_CACHE = await asyncio.to_thread(fetch_cisa)
    except Exception: pass
    SYSTEM_STATE["intel_sync_complete"] = True

async def auto_scan_loop():
    global AUTOSCAN_INTERVAL, TARGET_SUBNET, last_scan_time, last_purge_time, DEVICE_TELEMETRY
    while True:
        await asyncio.sleep(1)
        if (time.time() - last_purge_time) > 3600:
            current_time = time.time()
            stale_macs = [mac for mac, data in DEVICE_TELEMETRY.items() if (current_time - data.get("last_seen", 0)) > 172800]
            for mac in stale_macs: del DEVICE_TELEMETRY[mac]
            try:
                with closing(sqlite3.connect(DB_FILE, timeout=1.0)) as conn:
                    with conn: conn.cursor().execute("DELETE FROM alerts WHERE created_at < ?", (current_time - (7 * 24 * 3600),))
                last_purge_time = current_time
            except Exception: pass
        
        if AUTOSCAN_INTERVAL > 0 and (time.time() - last_scan_time) >= AUTOSCAN_INTERVAL:
            if SYSTEM_STATE["intel_sync_complete"]:
                await perform_network_scan(TARGET_SUBNET)
                last_scan_time = time.time()

def passive_packet_callback(pkt):
    if SYSTEM_STATE["sniffer_paused"]: return
    global ALERTED_MACS, DEVICE_TELEMETRY
    try:
        if pkt.haslayer(scapy.Ether):
            src_mac = pkt[scapy.Ether].src.upper()
            src_ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else "0.0.0.0"
            if src_mac in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"] or src_mac.startswith("33:33"): return

            if src_mac not in DEVICE_TELEMETRY:
                DEVICE_TELEMETRY[src_mac] = {"dhcp_name": "", "dhcp_prl": "", "mdns_name": "", "mdns_txt": "", "dns_queries": set(), "last_seen": 0}
            DEVICE_TELEMETRY[src_mac]["last_seen"] = time.time()

            if pkt.haslayer(scapy.DHCP):
                for opt in pkt[scapy.DHCP].options:
                    if isinstance(opt, tuple):
                        if opt[0] == 'hostname': DEVICE_TELEMETRY[src_mac]["dhcp_name"] = str(opt[1].decode('utf-8', errors='ignore') if isinstance(opt[1], bytes) else opt[1])
                        elif opt[0] == 'param_req_list': DEVICE_TELEMETRY[src_mac]["dhcp_prl"] = "".join(f"{x:02x}" for x in opt[1]) if isinstance(opt[1], list) else opt[1].hex()

            if pkt.haslayer(scapy.UDP) and pkt.haslayer(scapy.DNS):
                if pkt[scapy.DNS].qd:
                    qname = pkt[scapy.DNS].qd.qname
                    if isinstance(qname, bytes): qname = qname.decode('utf-8', errors='ignore')
                    
                    if pkt[scapy.UDP].dport == 5353 and qname.endswith('.local.') and '_' not in qname: 
                        DEVICE_TELEMETRY[src_mac]["mdns_name"] = qname.replace('.local.', '')
                    elif pkt[scapy.UDP].dport == 53: 
                        domain = qname.strip('.')
                        if len(DEVICE_TELEMETRY[src_mac]["dns_queries"]) < 20: 
                            DEVICE_TELEMETRY[src_mac]["dns_queries"].add(domain)
                
                if pkt.haslayer(scapy.DNSRR) and pkt[scapy.UDP].dport == 5353:
                    for i in range(pkt[scapy.DNS].ancount):
                        rr = pkt[scapy.DNS].an[i]
                        if rr.type == 16: 
                            try:
                                rdata = b"".join(rr.rdata).decode('utf-8', errors='ignore')
                                if 'model=' in rdata or 'md=' in rdata: DEVICE_TELEMETRY[src_mac]["mdns_txt"] = rdata
                            except Exception: pass

            if src_mac in ALERTED_MACS: return
            with closing(sqlite3.connect(DB_FILE, timeout=1.0)) as conn:
                c = conn.cursor()
                if not c.execute("SELECT mac FROM devices WHERE mac = ?", (src_mac,)).fetchone():
                    with conn: c.execute("INSERT INTO alerts (mac, ip, timestamp, type, created_at) VALUES (?, ?, ?, ?, ?)", (src_mac, src_ip, datetime.now().strftime("%H:%M:%S"), "ROGUE_DEVICE_TRAP", time.time()))
                    ALERTED_MACS.add(src_mac)
                    trigger_webhook("🚨 Rogue Device Detected", f"A new device with MAC **{src_mac}** and IP **{src_ip}** was detected on the network.")
    except Exception: pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    global sniffer_handle, ALERTED_MACS, FINGERBANK_CACHE
    
    FINGERBANK_CACHE = {"0103060f1f212b2c2e2f7779f9fc": {"vendor": "Microsoft", "name": "Windows PC"}, "0103060f775ffc2c2e2f": {"vendor": "Apple", "name": "iOS/Mac Device"}, "0103060f1c21333a3b": {"vendor": "Google", "name": "Android Device"}}

    db_directory = os.path.dirname(DB_FILE)
    if db_directory and not os.path.exists(db_directory): os.makedirs(db_directory, exist_ok=True)

    with closing(sqlite3.connect(DB_FILE)) as conn:
        with conn:
            c = conn.cursor()
            c.execute("PRAGMA journal_mode=WAL;")
            c.execute('''CREATE TABLE IF NOT EXISTS devices (mac TEXT PRIMARY KEY, vendor TEXT, custom_name TEXT, tags TEXT, icon_override TEXT, hostname TEXT DEFAULT '', device_type TEXT DEFAULT '')''')
            c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, mac TEXT, ip TEXT, status TEXT, vulnerabilities TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, timestamp TEXT, type TEXT, created_at REAL)''')
            c.execute("SELECT mac FROM alerts")
            ALERTED_MACS.update(row[0] for row in c.fetchall())

    bpf_rule = "udp port 67 or udp port 68 or udp port 5353 or udp port 53"
    try:
        sniffer_handle = scapy.AsyncSniffer(prn=passive_packet_callback, store=0, filter=bpf_rule, iface=TARGET_INTERFACE)
        sniffer_handle.start()
    except Exception as e: print(f"[⚠️ SNIFFER] Passive monitoring failure. Error: {e}")

    asyncio.create_task(background_intel_sync())
    asyncio.create_task(auto_scan_loop())
    asyncio.create_task(background_nmap_sync())
    yield
    if sniffer_handle: sniffer_handle.stop()

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# =====================================================================
# 4. ACTIVE REMEDIATION MODULE (ARP Quaratine & WoL)
# =====================================================================

async def arp_quarantine_task(target_mac, target_ip):
    try:
        gw_ip = scapy.conf.route.route("0.0.0.0")[2]
        if not gw_ip or gw_ip == "0.0.0.0": return
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=gw_ip), timeout=2, verbose=False, iface=TARGET_INTERFACE)
        if not ans: return
        gw_mac = ans[0][1].hwsrc
        server_mac = scapy.get_if_hwaddr(TARGET_INTERFACE)

        pkt_to_target = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gw_ip, hwdst=target_mac, hwsrc=server_mac)
        pkt_to_gw = scapy.Ether(dst=gw_mac)/scapy.ARP(op=2, pdst=gw_ip, psrc=target_ip, hwdst=gw_mac, hwsrc=server_mac)

        print(f"[🛡️ IPS] Initiating localized ARP quarantine on {target_mac}")
        while target_mac in ACTIVE_QUARANTINES:
            scapy.sendp(pkt_to_target, verbose=False, iface=TARGET_INTERFACE)
            scapy.sendp(pkt_to_gw, verbose=False, iface=TARGET_INTERFACE)
            await asyncio.sleep(2.0)
            
    except Exception as e:
        print(f"[⚠️ IPS] Quarantine failed for {target_mac}: {e}")
        if target_mac in ACTIVE_QUARANTINES: ACTIVE_QUARANTINES.remove(target_mac)

@app.post("/api/device/{mac}/quarantine")
async def toggle_quarantine(mac: str):
    mac = mac.upper()
    if mac in ACTIVE_QUARANTINES:
        ACTIVE_QUARANTINES.remove(mac)
        trigger_webhook("🟢 Isolation Lifted", f"Asset **{mac}** has been released from ARP quarantine.", 65280)
        return {"success": True, "message": "Quarantine lifted. Device connectivity restored."}
    else:
        with closing(sqlite3.connect(DB_FILE)) as conn:
            row = conn.cursor().execute("SELECT ip FROM scans WHERE mac=? ORDER BY id DESC LIMIT 1", (mac,)).fetchone()
        if not row: return {"success": False, "detail": "Cannot quarantine: No known IP address for this MAC."}
        
        target_ip = row[0].split(',')[0].strip()
        ACTIVE_QUARANTINES.add(mac)
        asyncio.create_task(arp_quarantine_task(mac, target_ip))
        trigger_webhook("🛑 Isolation Triggered", f"Asset **{mac}** has been actively blackholed via ARP poisoning.", 16711680)
        return {"success": True, "message": "ARP Poisoning activated. Device isolated."}

@app.post("/api/device/{mac}/wake")
def wake_device(mac: str):
    try:
        mac_clean = mac.replace(':', '').replace('-', '')
        if len(mac_clean) != 12: raise ValueError("Invalid MAC Address format")
        magic_packet = b'\xff' * 6 + bytes.fromhex(mac_clean) * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic_packet, ('255.255.255.255', 9))
        return {"success": True, "message": "Magic Packet UDP Broadcast Sent."}
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

# =====================================================================
# 5. API ENDPOINTS & UTILITIES
# =====================================================================
def get_icon_for_vendor(vendor_name, device_type=""):
    v, t = (vendor_name or "").lower(), (device_type or "").lower()
    if any(x in t for x in ["iphone", "ipad", "pixel", "galaxy", "phone", "mobile", "android", "ios"]): return "📱"
    if any(x in t for x in ["macbook", "workstation", "laptop", "desktop", "pc", "windows", "imac", "thinkpad"]): return "💻"
    if any(x in t for x in ["tv", "roku", "chromecast", "apple tv", "bravia", "firestick", "fire tv", "shield", "display", "monitor", "webos", "tizen"]): return "📺"
    if any(x in t for x in ["playstation", "xbox", "nintendo", "console", "switch"]): return "🎮"
    if any(x in t for x in ["camera", "cam", "cctv", "nvr", "dvr", "hikvision", "dahua"]): return "📷"
    if any(x in t for x in ["nas", "server", "proxmox", "linux", "ubuntu", "debian", "centos", "redhat", "truenas"]): return "🗄️"
    if any(x in t for x in ["printer", "print", "copier", "fax"]): return "🖨️"
    if any(x in t for x in ["speaker", "sonos", "audio", "soundbar", "alexa", "echo", "homepod", "sound"]): return "🔊"
    if any(x in t for x in ["light", "bulb", "switch", "plug", "relay", "shelly", "sonoff", "smart"]): return "💡"
    if any(x in t for x in ["router", "gateway", "switch", "ap", "access point", "firewall", "unifi", "hub"]): return "🌐"

    if "private" in v or "randomized" in v: return "🔒"
    if any(x in v for x in ["nintendo", "sony interactive", "valve", "sega", "atari"]): return "🎮"
    if any(x in v for x in ["brother", "epson", "canon", "lexmark", "ricoh", "xerox", "kyocera", "zebra", "konica", "fuji"]): return "🖨️"
    if any(x in v for x in ["synology", "qnap", "asustor", "seagate", "western digital", "buffalo"]): return "🗄️"
    if any(x in v for x in ["ring", "arlo", "wyze", "blink", "hikvision", "dahua", "axis communications", "reolink", "amcrest", "eufy"]): return "📷"
    if any(x in v for x in ["amazon", "sonos", "bose", "jbl", "harman", "bang & olufsen", "denon", "marantz", "yamaha", "pioneer", "sennheiser"]): return "🔊"
    if any(x in v for x in ["roku", "vizio", "tcl", "hisense", "lg electronics", "lg ", "samsung", "sony"]): return "📺"
    if any(x in v for x in ["ge lighting", "espressif", "tuya", "broadlink", "sonoff", "shelly", "aqara", "signify", "philips", "lutron", "belkin", "wemo", "tp-link kasa", "lifx"]): return "💡"
    if any(x in v for x in ["shenzhen", "sjit", "delta electronics", "hon hai", "foxconn", "pegatron", "compal", "realtek", "mediatek", "texas instruments", "murata", "liteon", "azurewave", "icomm", "phaten"]): return "🔌"
    if any(x in v for x in ["apple", "google", "xiaomi", "oneplus", "oppo", "vivo", "huawei", "honor", "sony mobile", "htc", "motorola"]): return "📱"
    if any(x in v for x in ["intel", "dell", "hp ", "hewlett-packard", "lenovo", "microsoft", "acer", "asustek", "asus", "msi", "gigabyte", "super micro", "fujitsu", "toshiba", "panasonic", "ibm"]): return "💻"
    if any(x in v for x in ["netgear", "cisco", "ubiquiti", "tp-link", "linksys", "mikrotik", "aruba", "d-link", "zte", "fortinet", "juniper", "sophos", "netgate", "pfsense", "arris", "technicolor", "commscope", "sagemcom"]): return "🌐"
    if any(x in v for x in ["vmware", "citrix", "xen", "oracle", "proxmox", "docker", "red hat"]): return "☁️"
    return "❓"

async def fetch_http_title(ip: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.6)
        writer.write(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=0.6)
        writer.close(); await writer.wait_closed()
        text = data.decode('utf-8', errors='ignore')
        match = re.search(r'(?i)<title>(.*?)</title>', text)
        if match: return match.group(1).strip()
    except Exception: pass
    return ""

async def query_fingerprint_api(mac: str, ip: str, open_ports: list, telemetry: dict, scraped_title: str) -> dict:
    mac_upper, prefix_3b = mac.upper(), mac.upper()[:8]
    base_vendor = "Private/Randomized MAC" if (len(mac_upper) > 1 and mac_upper[1] in ['2', '6', 'A', 'E']) else None
    if not base_vendor:
        try: base_vendor = await mac_checker.lookup(mac_upper)
        except Exception: base_vendor = None
    if not base_vendor or "Unknown" in base_vendor:
        base_vendor = LOCAL_OUI_FALLBACK.get(prefix_3b, "Unknown Hardware")
    
    identity = {"vendor": base_vendor, "hostname": "", "device_type": "", "icon": "", "tags": ""}

    if ip in NMAP_CACHE:
        nd = NMAP_CACHE[ip]
        if nd["nmap_name"]: identity["hostname"] = nd["nmap_name"]
        if nd["vendor_dict"] and mac in nd["vendor_dict"]: identity["vendor"] = nd["vendor_dict"][mac]
        if nd["os"]: identity["tags"] = f"[{nd['os']}]"

    if not identity["hostname"]: identity["hostname"] = telemetry.get("dhcp_name") or telemetry.get("mdns_name") or ""
    c_name = identity["hostname"]
    for scrap in ["._companion-link._tcp", "._apple-mobdev2._tcp", "._tcp", "_tcp"]: c_name = c_name.replace(scrap, "")
    identity["hostname"] = c_name.strip(" .-_")

    if scraped_title: identity["device_type"] = scraped_title

    txt = telemetry.get("mdns_txt", "")
    if txt and not identity["device_type"]:
        m = re.search(r'(?:model|md)=([^,; ]+)', txt)
        if m: identity["device_type"] = m.group(1)

    dns_history = telemetry.get("dns_queries", set())
    if not identity["device_type"]:
        dns_string = " ".join(dns_history).lower()
        if "nintendo.net" in dns_string: identity["device_type"], identity["vendor"] = "Nintendo Switch", "Nintendo"
        elif "playstation.net" in dns_string: identity["device_type"], identity["vendor"] = "PlayStation Console", "Sony"
        elif "netflix.com" in dns_string and "Smart TV" not in identity["device_type"]: identity["device_type"] = "Media Streaming Device"
        elif "wyze.com" in dns_string: identity["device_type"], identity["vendor"] = "Wyze Camera", "Wyze"

    if not identity["device_type"]:
        if 9304 in open_ports: identity["device_type"], identity["vendor"] = "PlayStation Console", "Sony"
        elif 8009 in open_ports: identity["device_type"], identity["vendor"] = "Chromecast / Google Node", "Google"
        elif 62078 in open_ports: identity["device_type"], identity["vendor"] = "Apple iOS Device", "Apple Inc."
        elif 554 in open_ports: identity["device_type"] = "IP Security Camera"
        elif 32400 in open_ports: identity["device_type"] = "Plex Media Server"
        elif 9100 in open_ports or 515 in open_ports: identity["device_type"] = "Network Printer"
        
        prl = telemetry.get("dhcp_prl", "")
        if prl in FINGERBANK_CACHE:
            if "Unknown" in identity["vendor"] or "Private" in identity["vendor"]: identity["vendor"] = FINGERBANK_CACHE[prl]["vendor"]
            identity["device_type"] = identity["device_type"] or FINGERBANK_CACHE[prl]["name"]

    identity["icon"] = get_icon_for_vendor(identity["vendor"], identity["device_type"])
    return identity

class DeviceUpdate(BaseModel):
    custom_name: str; tags: str; icon_override: Optional[str] = None

class ScheduleUpdate(BaseModel):
    interval_minutes: int; subnet: str

@app.get("/")
def serve_dashboard(): 
    if os.path.exists(UI_FILE): return FileResponse(UI_FILE, headers={"Cache-Control": "no-cache, no-store, must-revalidate, max-age=0"})
    return Response(status_code=404)

@app.get("/favicon.ico", include_in_schema=False)
def disable_favicon(): return Response(status_code=204)

@app.post("/api/scan/schedule")
def update_schedule(config: ScheduleUpdate):
    global AUTOSCAN_INTERVAL, TARGET_SUBNET, last_scan_time
    AUTOSCAN_INTERVAL = config.interval_minutes * 60
    TARGET_SUBNET = config.subnet; last_scan_time = time.time()
    return {"success": True}

@app.get("/api/heartbeat")
def server_heartbeat():
    with closing(sqlite3.connect(DB_FILE)) as conn: count = conn.cursor().execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {"status": "online", "paused": SYSTEM_STATE["sniffer_paused"], "alert_count": count, "intel_sync_complete": SYSTEM_STATE["intel_sync_complete"]}

@app.post("/api/passive_alerts/pause")
def pause_alerts(): 
    SYSTEM_STATE["sniffer_paused"] = True; return {"success": True}

@app.post("/api/passive_alerts/resume")
def resume_alerts(): 
    SYSTEM_STATE["sniffer_paused"] = False; return {"success": True}

@app.get("/api/devices")
def get_devices_by_scan(scan_id: Optional[str] = Query(None)):
    with closing(sqlite3.connect(DB_FILE)) as conn:
        c = conn.cursor()
        if not scan_id:
            row = c.execute("SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            scan_id = row[0] if row else None
        if not scan_id: return {"success": True, "devices": [], "scan_id": None}
        
        rows = c.execute("""SELECT s.mac, s.ip, d.vendor, d.custom_name, d.tags, s.status, s.vulnerabilities, s.scan_id, d.icon_override, d.hostname, d.device_type FROM scans s LEFT JOIN devices d ON s.mac = d.mac WHERE s.scan_id = ?""", (scan_id,)).fetchall()
    
    devices = []
    for r in rows:
        mac_addr = r[0]
        vendor, c_name, d_type = r[2] or "Unknown", r[3], r[10] or ""
        
        # 1. Fetch real-time telemetry from memory for deep-dive diagnostics
        telem = DEVICE_TELEMETRY.get(mac_addr, {})
        
        # 2. Extract Last Seen timestamp
        last_seen_ts = telem.get("last_seen", 0)
        if last_seen_ts > 0:
            last_seen_str = datetime.fromtimestamp(last_seen_ts).strftime("%Y-%m-%d %H:%M:%S")
        else:
            last_seen_str = r[7] # Fallback to active scan timestamp
            
        devices.append({
            "mac": mac_addr, "ip": r[1], "vendor": vendor, "icon": r[8] if r[8] else get_icon_for_vendor(vendor, d_type),
            "custom_name": c_name, "tags": r[4], "status": r[5], "vulnerabilities": json.loads(r[6]) if r[6] else [], 
            "scan_id": r[7], "icon_override": r[8], "hostname": r[9] or "", "device_type": d_type,
            "last_seen": last_seen_str,
            "dhcp_prl": telem.get("dhcp_prl", ""),
            "mdns_txt": telem.get("mdns_txt", ""),
            "dns_history": list(telem.get("dns_queries", set()))
        })
    return {"success": True, "devices": devices, "scan_id": scan_id}

@app.get("/api/topology")
def get_topology():
    with closing(sqlite3.connect(DB_FILE)) as conn:
        c = conn.cursor()
        row = c.execute("SELECT scan_id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row: return {"nodes": [], "edges": []}
        rows = c.execute("SELECT s.mac, s.ip, d.hostname, d.vendor FROM scans s LEFT JOIN devices d ON s.mac = d.mac WHERE s.scan_id = ? AND s.status = 'online'", (row[0],)).fetchall()
    
    nodes, edges = [{"id": "GATEWAY", "label": "Default Gateway\nRouter", "group": "gateway"}], []
    for r in rows:
        ip_primary = r[1].split(',')[0]
        nodes.append({"id": r[0], "label": f"{r[2] or r[3] or 'Unknown'}\n{ip_primary}", "group": "device"})
        edges.append({"from": "GATEWAY", "to": r[0]})
    return {"nodes": nodes, "edges": edges}

async def async_grab_banner(ip: str, port: int) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.25)
        if port in [80, 8080]:
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=0.20)
        banner = data.decode('utf-8', errors='ignore').strip()
        writer.close(); await writer.wait_closed()
        return banner if banner else f"Port {port} Open"
    except Exception: return None

async def run_parallel_fingerprinting(ip: str) -> List[dict]:
    tasks = [async_grab_banner(ip, p) for p in TARGET_PORTS]
    banners = await asyncio.gather(*tasks)
    vulns = []
    for i, banner in enumerate(banners):
        if banner:
            port = TARGET_PORTS[i]
            if port == 23: vulns.append({"id": "POLICY-CLEAR-TELNET", "description": "Telnet exposed.", "severity": "CRITICAL", "cvss": 9.8, "is_kev": True})
            else: vulns.append({"id": f"PORT-{port}-OPEN", "description": f"Service discovered: {banner[:60]}", "severity": "INFO", "cvss": 0.0, "is_kev": False})
    return vulns

def run_active_sweeps(subnet):
    discovered = {}
    def add_host(mac, ip):
        if mac and ip and mac not in ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"]:
            if mac not in discovered: discovered[mac] = set()
            discovered[mac].add(ip)

    try:
        ans_arp, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=subnet), timeout=3, retry=2, inter=0.02, verbose=False, iface=TARGET_INTERFACE)
        for s, r in ans_arp: add_host(r.hwsrc.upper(), r.psrc)
    except Exception: pass

    try:
        ans_icmp, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(dst=subnet)/scapy.ICMP(), timeout=3, retry=1, inter=0.02, verbose=False, iface=TARGET_INTERFACE, multi=True)
        for s, r in ans_icmp:
            if scapy.IP in r: add_host(r.src.upper(), r[scapy.IP].src)
    except Exception: pass

    return [{"mac": mac, "ips": ips} for mac, ips in discovered.items()]

@app.get("/api/scan")
async def perform_network_scan(subnet: str = Query("192.168.1.0/24")):
    if not SYSTEM_STATE["intel_sync_complete"]: return {"success": False, "error": "Intel databases syncing. Wait."}

    try:
        loop = asyncio.get_running_loop()
        raw_hosts = await loop.run_in_executor(None, run_active_sweeps, subnet)
        scan_id = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        semaphore = asyncio.Semaphore(12) 
        
        async def process_device(host):
            mac, primary_ip = host["mac"], list(host["ips"])[0] 
            async with semaphore:
                vulns = await run_parallel_fingerprinting(primary_ip)
                open_ports = [int(v["id"].split("-")[1]) for v in vulns if v["id"].startswith("PORT-")]
                web_ports = [p for p in open_ports if p in [80, 443, 8000, 8080]]
                title_tasks = [fetch_http_title(primary_ip, p) for p in web_ports]
                scraped_titles = await asyncio.gather(*title_tasks) if title_tasks else []
                valid_titles = [t for t in scraped_titles if t]
                best_title = valid_titles[0] if valid_titles else ""
                identity = await query_fingerprint_api(mac, primary_ip, open_ports, DEVICE_TELEMETRY.get(mac, {}), best_title)
            
            return {
                "mac": mac, "ip": list(host["ips"]), "vendor": identity["vendor"], 
                "hostname": identity["hostname"], "device_type": identity["device_type"],
                "icon": identity["icon"], "tags": identity.get("tags", ""), "vulns": json.dumps(vulns)
            }

        raw_results = await asyncio.gather(*[process_device(h) for h in raw_hosts])

        unique_results = {}
        for dev in raw_results:
            mac = dev["mac"]
            if mac not in unique_results:
                unique_results[mac] = dev.copy()
                unique_results[mac]["ip_set"] = set(dev["ip"])
            else: unique_results[mac]["ip_set"].update(dev["ip"])

        results = []
        for mac, dev in unique_results.items():
            ips = list(dev["ip_set"])
            dev["ip"] = f"{ips[0]}, {ips[1]}, {ips[2]}, (+ proxy)" if len(ips) > 3 else ", ".join(ips)
            del dev["ip_set"]
            results.append(dev)

        with closing(sqlite3.connect(DB_FILE)) as conn:
            with conn:
                c = conn.cursor()
                for dev in results:
                    c.execute("INSERT OR IGNORE INTO devices (mac, vendor, custom_name, tags, icon_override, hostname, device_type) VALUES (?, ?, '', ?, '', ?, ?)", (dev["mac"], dev["vendor"], dev["tags"], dev["hostname"], dev["device_type"]))
                    c.execute("UPDATE devices SET vendor=?, hostname=?, device_type=? WHERE mac=?", (dev["vendor"], dev["hostname"], dev["device_type"], dev["mac"]))
                    if dev["tags"]: c.execute("UPDATE devices SET tags=? WHERE mac=? AND tags=''", (dev["tags"], dev["mac"]))
                
                scan_records = [(scan_id, dev["mac"], dev["ip"], 'online', dev["vulns"]) for dev in results]
                c.executemany("INSERT INTO scans (scan_id, mac, ip, status, vulnerabilities) VALUES (?, ?, ?, ?, ?)", scan_records)

                prev_row = c.execute("SELECT DISTINCT scan_id FROM scans WHERE scan_id != ? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
                if prev_row:
                    c.execute("SELECT mac, ip, vulnerabilities FROM scans WHERE scan_id = ? AND mac NOT IN (SELECT mac FROM scans WHERE scan_id = ?)", (prev_row[0], scan_id))
                    offline_records = [(scan_id, off[0], off[1], 'offline', off[2]) for off in c.fetchall()]
                    if offline_records: c.executemany("INSERT INTO scans (scan_id, mac, ip, status, vulnerabilities) VALUES (?, ?, ?, ?, ?)", offline_records)
        return get_devices_by_scan(scan_id)
    except Exception as e: return {"success": False, "error": str(e)}

@app.post("/api/device/{mac}/update")
def update_device(mac: str, update_data: DeviceUpdate):
    with closing(sqlite3.connect(DB_FILE)) as conn:
        with conn: conn.cursor().execute("UPDATE devices SET custom_name=?, tags=?, icon_override=? WHERE mac=?", (update_data.custom_name, update_data.tags, update_data.icon_override, mac.upper()))
    return {"success": True}

@app.get("/api/scan_history")
def get_scan_history():
    with closing(sqlite3.connect(DB_FILE)) as conn: return {"success": True, "history": [r[0] for r in conn.cursor().execute("SELECT DISTINCT scan_id FROM scans ORDER BY scan_id DESC").fetchall()]}

@app.post("/api/passive_alerts/clear")
def clear_passive_alerts():
    global ALERTED_MACS; ALERTED_MACS.clear()
    with closing(sqlite3.connect(DB_FILE)) as conn:
        with conn: conn.cursor().execute("DELETE FROM alerts")
    return {"success": True}

@app.get("/api/passive_alerts")
def get_passive_alerts(): 
    with closing(sqlite3.connect(DB_FILE)) as conn:
        conn.row_factory = sqlite3.Row
        return {"success": True, "alerts": [dict(row) for row in conn.cursor().execute("SELECT mac, ip, timestamp, type FROM alerts ORDER BY id ASC").fetchall()]}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*50)
    print(f"🚀 SecOps Core Backend Online binding to {HOST}:{PORT}")
    print("="*50 + "\n")
    module_name = os.path.splitext(os.path.basename(__file__))[0]
    uvicorn.run(f"{module_name}:app", host=HOST, port=PORT, reload=True, log_level="warning")
