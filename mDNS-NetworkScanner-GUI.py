import sys
import subprocess
import logging
import os
import json

# ============================================================
# Suppress Scapy pcap/libpcap warnings at startup
# ============================================================
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
os.environ["PYWARN"] = "ignore"

# Disable Scapy's warning printouts on stdout/stderr before import
sys.stderr_bak = sys.stderr
sys.stderr = open(os.devnull, 'w')

# ============================================================
# Auto-Install Missing Dependencies
# ============================================================

REQUIRED_PACKAGES = {
    "zeroconf": "zeroconf",
    "scapy": "scapy",
    "mac_vendor_lookup": "mac-vendor-lookup",
    "openpyxl": "openpyxl"
}

def install_missing_packages():
    missing = []
    for module_name, pip_name in REQUIRED_PACKAGES.items():
        try:
            __import__(module_name)
        except ImportError:
            missing.append(pip_name)
            
    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print("Automatically installing via pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
            print("Dependencies successfully installed!\n")
        except Exception as e:
            print(f"Error installing packages automatically: {e}")
            sys.exit(1)

install_missing_packages()

import ipaddress
import socket
import concurrent.futures
import re
import time
import ctypes
import threading
import csv

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

try:
    from zeroconf import ServiceBrowser, Zeroconf
    import scapy.all as scapy
    from mac_vendor_lookup import MacLookup
finally:
    # Restore standard stderr after Scapy import finishes
    sys.stderr = sys.stderr_bak

# Initialize live MAC lookup engine
try:
    mac_lookup_engine = MacLookup()
    try:
        mac_lookup_engine.update_vendors()
    except Exception:
        pass
except Exception:
    mac_lookup_engine = None


# ============================================================
# Persistent MAC Mapping Subsystem
# ============================================================

MAPPING_FILE = "mDNS-NetworkScanner-Mapping.json"

def load_mac_mappings():
    """Loads saved MAC address and note mappings from local JSON storage."""
    if os.path.exists(MAPPING_FILE):
        try:
            with open(MAPPING_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_mac_mapping(mac_address, ip_address, note_text):
    """Saves or updates a MAC/IP note mapping in the persistent JSON store."""
    mappings = load_mac_mappings()
    key = mac_address.upper() if mac_address and mac_address != "N/A" else f"IP:{ip_address}"
    
    mappings[key] = {
        "mac": mac_address,
        "last_ip": ip_address,
        "note": note_text,
        "updated": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    try:
        with open(MAPPING_FILE, "w", encoding="utf-8") as f:
            json.dump(mappings, f, indent=4)
    except Exception as e:
        print(f"Error saving MAC mapping reference file: {e}")

def lookup_saved_note(mac_address, ip_address):
    """Retrieves a previously stored note for a MAC address or IP."""
    mappings = load_mac_mappings()
    if mac_address and mac_address != "N/A" and mac_address.upper() in mappings:
        return mappings[mac_address.upper()].get("note", "")
    
    ip_key = f"IP:{ip_address}"
    if ip_key in mappings:
        return mappings[ip_key].get("note", "")
        
    return ""


# ============================================================
# Global Settings & Tuning Defaults
# ============================================================

PING_WORKERS = 100
ARP_WORKERS = 50
HOSTNAME_WORKERS = 30
PORT_SCAN_WORKERS = 30

MDNS_SERVICE_DISCOVERY_TIME = 8
MDNS_DEVICE_DISCOVERY_TIME = 8

COMMON_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 8080]


# ============================================================
# Layer 3 ICMP Ping Engine
# ============================================================

def ping_host(ip_str, cancel_event=None):
    """Executes a fast ICMP echo request using native system ping."""
    if cancel_event and cancel_event.is_set():
        return False
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "350", ip_str],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================
# Native Win32 ARP Engine
# ============================================================

def send_arp_probe(ip_str, cancel_event=None):
    """
    Sends a direct Layer 2 ARP request via Windows iphlpapi.dll.
    Does NOT require Npcap/libpcap drivers to work reliably on Windows.
    """
    if cancel_event and cancel_event.is_set():
        return None
    try:
        inet_addr = socket.inet_aton(ip_str)
        ip_int = ctypes.c_ulong(int.from_bytes(inet_addr, byteorder='little'))
        
        mac_addr = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        
        result = ctypes.windll.iphlpapi.SendARP(ip_int, 0, ctypes.byref(mac_addr), ctypes.byref(mac_len))
        
        if result == 0:
            bytes_mac = bytes(mac_addr)
            return ":".join(f"{b:02X}" for b in bytes_mac)
    except Exception:
        pass

    try:
        arp_request = scapy.ARP(pdst=ip_str)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=0.5, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc.upper()
    except Exception:
        pass

    return None


# ============================================================
# Network Detection & Range Parsing Engine
# ============================================================

def get_network_adapters():
    """Reads Windows ipconfig and returns active local IPv4 networks."""
    result = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    networks = []
    current_adapter = None
    current_ip = None
    current_mask = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()

        adapter_match = re.match(r"^(.*adapter\s+)(.+):$", line, re.IGNORECASE)
        if adapter_match:
            current_adapter = adapter_match.group(2).strip()
            current_ip = None
            current_mask = None
            continue

        if "IPv4 Address" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                current_ip = match.group(1)

        elif "Subnet Mask" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                current_mask = match.group(1)

        if current_adapter and current_ip and current_mask:
            try:
                interface = ipaddress.ip_interface(f"{current_ip}/{current_mask}")
                network = interface.network

                if interface.ip.is_loopback:
                    current_ip = None
                    current_mask = None
                    continue

                existing = None
                for item in networks:
                    if item["network"] == network:
                        existing = item
                        break

                if existing:
                    if current_ip not in existing["ips"]:
                        existing["ips"].append(current_ip)
                    if current_adapter not in existing["adapters"]:
                        existing["adapters"].append(current_adapter)
                else:
                    networks.append({
                        "network": network,
                        "adapters": [current_adapter],
                        "ips": [current_ip]
                    })

                current_ip = None
                current_mask = None

            except ValueError:
                pass

    return networks


def parse_custom_range(user_input):
    """Parses custom CIDR notation, hyphenated ranges, or single IP strings."""
    user_input = user_input.strip()

    if "/" in user_input:
        net = ipaddress.ip_network(user_input, strict=False)
        return list(net.hosts()) if net.prefixlen < 32 else [net.network_address]

    if "-" in user_input:
        parts = user_input.split("-")
        start_str = parts[0].strip()
        end_str = parts[1].strip()

        start_ip = ipaddress.ip_address(start_str)

        if "." in end_str:
            end_ip = ipaddress.ip_address(end_str)
        else:
            base_octets = start_str.split(".")[:-1]
            end_ip = ipaddress.ip_address(".".join(base_octets + [end_str]))

        start_int = int(start_ip)
        end_int = int(end_ip)

        if start_int > end_int:
            start_int, end_int = end_int, start_int

        return [ipaddress.ip_address(ip) for ip in range(start_int, end_int + 1)]

    return [ipaddress.ip_address(user_input)]


# ============================================================
# Hostname, NetBIOS, Live Vendor & Smart Fallback Engine
# ============================================================

def get_netbios_name(ip):
    """Attempts NetBIOS hostname lookup using Windows nbtstat."""
    try:
        result = subprocess.run(
            ["nbtstat", "-A", str(ip)],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=1.2
        )

        for line in result.stdout.splitlines():
            match = re.search(
                r"^\s*([A-Za-z0-9_\-\.]+)\s+<00>\s+UNIQUE",
                line,
                re.IGNORECASE
            )

            if match:
                name = match.group(1).strip()
                if name and not name.upper().startswith("WORKGROUP"):
                    return name

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass

    return None


def resolve_host_info(ip, cancel_event=None):
    """Resolves DNS and NetBIOS hostname information."""
    if cancel_event and cancel_event.is_set():
        return ""
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        if hostname and hostname != str(ip):
            return hostname
    except (socket.herror, socket.gaierror):
        pass

    netbios_name = get_netbios_name(ip)
    if netbios_name:
        return f"{netbios_name} (NetBIOS)"

    return ""


def get_vendor_by_mac(mac):
    """Performs live OUI Vendor Lookup."""
    if not mac or mac in ["N/A", "Gateway (Proxy)"] or not mac_lookup_engine:
        return ""
    try:
        vendor = mac_lookup_engine.lookup(mac)
        return vendor.strip()
    except Exception:
        pass
    return ""


def infer_smart_hostname(mac, open_ports_str):
    """Infers device class when hostnames cannot be resolved."""
    is_randomized_mac = False
    if mac and len(mac) >= 2:
        second_char = mac[1].upper()
        if second_char in ['2', '6', 'A', 'E']:
            is_randomized_mac = True

    ports = [p.strip() for p in open_ports_str.split(",") if p.strip().isdigit()]
    
    if "80" in ports or "443" in ports or "8080" in ports:
        return "[Web/Network Device]"
    if "135" in ports or "139" in ports or "445" in ports or "3389" in ports:
        return "[Windows Workstation/Server]"
    if "22" in ports:
        return "[Linux/SSH Host]"
    if "21" in ports or "23" in ports:
        return "[Legacy Device]"
    if is_randomized_mac:
        return "[Mobile/Private MAC Device]"

    return "[Active Host]"


# ============================================================
# ARP Table & Gateway Subsystem
# ============================================================

def get_arp_table():
    """Reads the system ARP cache."""
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    arp_devices = {}
    for line in result.stdout.splitlines():
        match = re.search(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+dynamic", line)
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            arp_devices[ip] = mac
    return arp_devices


def get_default_gateway_mac():
    """Identifies the default gateway's MAC address."""
    try:
        result = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3:
                    gw_ip = parts[2]
                    arp_table = get_arp_table()
                    return arp_table.get(gw_ip)
    except Exception:
        pass
    return None


# ============================================================
# mDNS Discovery Subsystem
# ============================================================

def mdns_discover(hosts_set, cancel_event=None, status_callback=None):
    """Executes active mDNS service discovery across target subnet."""
    if cancel_event and cancel_event.is_set():
        return {}

    if status_callback:
        status_callback("mDNS Discovery: Querying network service types...")

    service_types = set()

    def discover_service_types():
        discovered = set()
        zeroconf = Zeroconf()

        def service_type_handler(zeroconf=None, service_type=None, name=None, state_change=None, **kwargs):
            if name is None or state_change is None:
                return
            if getattr(state_change, "name", "") != "Added":
                return
            if name.endswith("._tcp.local.") or name.endswith("._udp.local."):
                discovered.add(name)

        browser = ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", handlers=[service_type_handler])
        
        for _ in range(MDNS_SERVICE_DISCOVERY_TIME * 10):
            if cancel_event and cancel_event.is_set():
                break
            time.sleep(0.1)

        browser.cancel()
        zeroconf.close()
        return discovered

    service_types.update(discover_service_types())

    if not service_types or (cancel_event and cancel_event.is_set()):
        return {}

    if status_callback:
        status_callback(f"mDNS Discovery: Querying {len(service_types)} service profiles...")

    mdns_devices = {}
    browsers = []
    zeroconf = Zeroconf()

    def service_handler(zeroconf=None, service_type=None, name=None, state_change=None, **kwargs):
        if cancel_event and cancel_event.is_set():
            return
        if name is None or service_type is None or state_change is None:
            return
        if getattr(state_change, "name", "") != "Added":
            return

        try:
            info = zeroconf.get_service_info(service_type, name, timeout=2000)
            if not info or not info.server:
                return

            hostname = info.server
            addresses = info.parsed_addresses()

            for address in addresses:
                try:
                    parsed_ip = ipaddress.ip_address(address)
                    if parsed_ip.version != 4 or address not in hosts_set:
                        continue
                except ValueError:
                    continue

                if address not in mdns_devices:
                    mdns_devices[address] = {"hostname": hostname, "services": set()}
                elif not mdns_devices[address]["hostname"]:
                    mdns_devices[address]["hostname"] = hostname

                mdns_devices[address]["services"].add(service_type)
        except Exception:
            pass

    for service_type in sorted(service_types):
        if cancel_event and cancel_event.is_set():
            break
        try:
            browser = ServiceBrowser(zeroconf, service_type, handlers=[service_handler])
            browsers.append(browser)
        except Exception:
            pass

    for _ in range(MDNS_DEVICE_DISCOVERY_TIME * 10):
        if cancel_event and cancel_event.is_set():
            break
        time.sleep(0.1)

    for browser in browsers:
        browser.cancel()
    zeroconf.close()

    return mdns_devices


# ============================================================
# TCP Port Audit Engine
# ============================================================

def scan_single_port(ip, port, cancel_event=None):
    """Connects to a single TCP port with tight timeout constraints."""
    if cancel_event and cancel_event.is_set():
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            if s.connect_ex((str(ip), port)) == 0:
                return port
    except Exception:
        pass
    return None


def scan_open_ports(ip, cancel_event=None):
    """Scans common TCP ports concurrently."""
    if cancel_event and cancel_event.is_set():
        return "None"
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = [executor.submit(scan_single_port, ip, port, cancel_event) for port in COMMON_PORTS]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    open_ports.sort()
    return ", ".join(str(p) for p in open_ports) if open_ports else "None"


# ============================================================
# Complete Multi-Layer Scanner Driver
# ============================================================

def scan_network_gui(hosts, discovery_mode="fast", status_callback=None, cancel_event=None):
    hosts = list(hosts)
    hosts_set = set(str(ip) for ip in hosts)
    total = len(hosts)

    # 1. Multi-Threaded ICMP Ping Sweep
    if status_callback:
        status_callback(f"Scanning [Phase 1/5]: Multithreaded ICMP Ping Sweep ({total} targets)...")

    ping_hits = set()
    completed_pings = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as executor:
        futures = {executor.submit(ping_host, str(ip), cancel_event): str(ip) for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            ip = futures[future]
            completed_pings += 1
            if future.result():
                ping_hits.add(ip)
            if status_callback and completed_pings % 15 == 0:
                status_callback(f"Scanning [Phase 1/5]: ICMP Ping {completed_pings}/{total} ({completed_pings/total*100:.0f}%)")

    if cancel_event and cancel_event.is_set():
        return {}

    # 2. Layer-2 ARP Request Probing via Win32 API
    if status_callback:
        status_callback(f"Scanning [Phase 2/5]: Win32 Native ARP Probing...")

    direct_arp_hits = {}
    completed_arps = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=ARP_WORKERS) as executor:
        futures = {executor.submit(send_arp_probe, str(ip), cancel_event): str(ip) for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            ip = futures[future]
            completed_arps += 1
            try:
                mac = future.result()
                if mac:
                    direct_arp_hits[ip] = mac
            except Exception:
                pass

    if cancel_event and cancel_event.is_set():
        return {}

    system_arp = get_arp_table()
    combined_arp = {**system_arp, **direct_arp_hits}
    subnet_arp = {ip: mac for ip, mac in combined_arp.items() if ip in hosts_set}

    gateway_mac = get_default_gateway_mac()

    # 3. Optional Active mDNS Sweep
    mdns_devices = {}
    if discovery_mode == "thorough" and not (cancel_event and cancel_event.is_set()):
        if status_callback:
            status_callback("Scanning [Phase 3/5]: Running mDNS Discovery...")
        mdns_devices = mdns_discover(hosts_set, cancel_event=cancel_event, status_callback=status_callback)

    if cancel_event and cancel_event.is_set():
        return {}

    candidate_ips = sorted(
        list(set(ping_hits) | set(subnet_arp.keys()) | set(mdns_devices.keys())),
        key=ipaddress.ip_address
    )

    # 4. Hostname & NetBIOS Resolution
    if status_callback:
        status_callback(f"Scanning [Phase 4/5]: Resolving hostnames for {len(candidate_ips)} active host(s)...")

    resolved_hostnames = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=HOSTNAME_WORKERS) as executor:
        futures = {executor.submit(resolve_host_info, ip, cancel_event): ip for ip in candidate_ips}
        for future in concurrent.futures.as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            ip = futures[future]
            try:
                name = future.result()
                if name:
                    resolved_hostnames[ip] = name
            except Exception:
                pass

    if cancel_event and cancel_event.is_set():
        return {}

    # 5. TCP Port Scanning
    if status_callback:
        status_callback(f"Scanning [Phase 5/5]: Auditing TCP ports for active host(s)...")

    scanned_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as executor:
        futures = {executor.submit(scan_open_ports, ip, cancel_event): ip for ip in candidate_ips}
        for future in concurrent.futures.as_completed(futures):
            if cancel_event and cancel_event.is_set():
                break
            ip = futures[future]
            try:
                scanned_ports[ip] = future.result()
            except Exception:
                scanned_ports[ip] = "None"

    if cancel_event and cancel_event.is_set():
        return {}

    # Consolidate Discovery Data and auto-fetch saved MAC notes
    devices = {}
    for ip in candidate_ips:
        mac = subnet_arp.get(ip, "")
        dns_netbios_name = resolved_hostnames.get(ip, "")
        mdns_name = mdns_devices.get(ip, {}).get("hostname", "")
        open_ports = scanned_ports.get(ip, "None")

        hostname = mdns_name or dns_netbios_name
        is_proxy_mac = (mac == gateway_mac and gateway_mac is not None)

        real_mac = mac if not is_proxy_mac else ""
        vendor = get_vendor_by_mac(real_mac)

        if not hostname and vendor:
            hostname = f"[{vendor}]"

        if not hostname:
            hostname = infer_smart_hostname(real_mac, open_ports)

        methods = []
        if ip in ping_hits:
            methods.append("ICMP Ping")
        if ip in direct_arp_hits:
            methods.append("ARP Direct")
        elif mac:
            methods.append("ARP Cache")
        if ip in mdns_devices:
            methods.append("mDNS")
        if dns_netbios_name:
            methods.append("DNS/NetBIOS")
        if open_ports != "None":
            methods.append("TCP Port")

        saved_note = lookup_saved_note(real_mac, ip)

        devices[ip] = {
            "mac": mac if mac else "N/A",
            "vendor": vendor if vendor else ("Gateway/Proxy" if is_proxy_mac else "Unknown Vendor"),
            "hostname": hostname,
            "method": " + ".join(methods) if methods else "Active Probe",
            "ports": open_ports,
            "notes": saved_note
        }

    return devices


# ============================================================
# Graphical User Interface (Tkinter)
# ============================================================

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("mDNS & Network Scanner - Active Controls & Live Filtering")
        self.root.geometry("1360x760")
        self.root.minsize(1040, 580)

        self.adapters = get_network_adapters()
        self.scan_results = {}
        self.cancel_event = threading.Event()
        self.is_scan_running = False

        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)

    def create_widgets(self):
        # 1. Top Configuration Frame
        ctrl_frame = ttk.LabelFrame(self.root, text=" Network Selection & Configuration ", padding=10)
        ctrl_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(ctrl_frame, text="Interface / Subnet:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        self.adapter_var = tk.StringVar()
        self.adapter_combo = ttk.Combobox(ctrl_frame, textvariable=self.adapter_var, width=50, state="readonly")
        
        combo_values = []
        for net in self.adapters:
            net_str = str(net['network'])
            ip_str = ", ".join(net['ips'])
            adapter_str = ", ".join(net['adapters'])
            combo_values.append(f"{net_str} ({ip_str}) - {adapter_str}")
        
        combo_values.append("Custom IP / Range / CIDR...")
        self.adapter_combo['values'] = combo_values
        if combo_values:
            self.adapter_combo.current(0)
        self.adapter_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.adapter_combo.bind("<<ComboboxSelected>>", self.on_adapter_select)

        ttk.Label(ctrl_frame, text="Custom Range:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.custom_entry = ttk.Entry(ctrl_frame, width=28, state="disabled")
        self.custom_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(ctrl_frame, text="Discovery Mode:").grid(row=0, column=2, sticky=tk.W, padx=12, pady=5)
        self.mode_var = tk.StringVar(value="fast")
        ttk.Radiobutton(ctrl_frame, text="Fast Scan (Ping + ARP + NetBIOS + Ports)", variable=self.mode_var, value="fast").grid(row=0, column=3, sticky=tk.W)
        ttk.Radiobutton(ctrl_frame, text="Thorough Scan (Fast + Full mDNS)", variable=self.mode_var, value="thorough").grid(row=1, column=3, sticky=tk.W)

        # Action Buttons Box
        btn_box = ttk.Frame(ctrl_frame)
        btn_box.grid(row=0, column=4, rowspan=2, padx=10, pady=5, sticky="NSEW")

        self.scan_btn = ttk.Button(btn_box, text="Start Scan", command=self.start_scan_thread, width=12)
        self.scan_btn.pack(side=tk.TOP, fill=tk.X, pady=2)

        self.stop_btn = ttk.Button(btn_box, text="Stop Scan", command=self.stop_scan, state="disabled", width=12)
        self.stop_btn.pack(side=tk.TOP, fill=tk.X, pady=2)

        self.export_btn = ttk.Button(btn_box, text="Export Excel", command=self.export_to_excel, width=12)
        self.export_btn.pack(side=tk.TOP, fill=tk.X, pady=2)

        # 2. Live Search & Filter Bar
        filter_frame = ttk.LabelFrame(self.root, text=" Live Search & Filter ", padding=8)
        filter_frame.pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(filter_frame, text="Filter Target:").pack(side=tk.LEFT, padx=(5, 5))
        self.filter_field_var = tk.StringVar(value="All Fields")
        self.filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_field_var,
            values=["All Fields", "IP Address", "MAC Address", "Vendor", "Hostname", "Open Ports", "Notes"],
            state="readonly",
            width=16
        )
        self.filter_combo.pack(side=tk.LEFT, padx=5)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

        ttk.Label(filter_frame, text="Search Query:").pack(side=tk.LEFT, padx=(15, 5))
        self.filter_query_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_query_var, width=38)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_query_var.trace_add("write", lambda *args: self.apply_filter())

        clear_filter_btn = ttk.Button(filter_frame, text="Clear Filter", command=self.clear_filter, width=11)
        clear_filter_btn.pack(side=tk.LEFT, padx=10)

        # 3. Results Table Frame
        tree_frame = ttk.Frame(self.root, padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "mac", "vendor", "hostname", "method", "ports", "notes")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Vendor / Manufacturer")
        self.tree.heading("hostname", text="Hostname / Resolved Device")
        self.tree.heading("method", text="Discovery Method")
        self.tree.heading("ports", text="Open Ports")
        self.tree.heading("notes", text="Notes (Double-Click to Edit / Auto-Saved)")

        self.tree.column("ip", width=110, anchor=tk.W)
        self.tree.column("mac", width=130, anchor=tk.W)
        self.tree.column("vendor", width=160, anchor=tk.W)
        self.tree.column("hostname", width=200, anchor=tk.W)
        self.tree.column("method", width=160, anchor=tk.W)
        self.tree.column("ports", width=110, anchor=tk.W)
        self.tree.column("notes", width=240, anchor=tk.W)

        self.tree.bind("<Double-1>", self.on_double_click)

        scrollbar_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=scrollbar_y.set, xscroll=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="NSEW")
        scrollbar_y.grid(row=0, column=1, sticky="NS")
        scrollbar_x.grid(row=1, column=0, sticky="EW")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # 4. Color-Coded Status Bar
        self.status_bar = tk.Label(
            self.root,
            text=" Status: Ready | Reference file: mDNS-NetworkScanner-Mapping.json",
            bg="#2E7D32",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            anchor=tk.W,
            padx=10,
            pady=6
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def set_status(self, text, status_type="running"):
        """
        Updates the status bar text and background color.
        status_type:
          - "running": Orange (#E65100)
          - "stopping": Amber (#D97706)
          - "stopped": Crimson Red (#B91C1C)
          - "ready": Green (#2E7D32)
        """
        color_map = {
            "running": "#E65100",
            "stopping": "#D97706",
            "stopped": "#B91C1C",
            "ready": "#2E7D32"
        }
        bg_color = color_map.get(status_type, "#2E7D32")
        
        def update():
            self.status_bar.config(text=f" Status: {text}", bg=bg_color)
        self.root.after(0, update)

    def on_adapter_select(self, event):
        if self.adapter_combo.get() == "Custom IP / Range / CIDR...":
            self.custom_entry.config(state="normal")
            self.custom_entry.focus()
        else:
            self.custom_entry.config(state="disabled")

    def stop_scan(self):
        """Triggers the cancellation event and updates status indicator."""
        if self.is_scan_running:
            self.cancel_event.set()
            self.stop_btn.config(state="disabled")
            self.set_status("Cancellation requested... Waiting for active thread pools to finalize...", status_type="stopping")

    def start_scan_thread(self):
        selected = self.adapter_combo.get()
        if not selected:
            messagebox.showwarning("Selection Warning", "Please select a network interface or custom range.")
            return

        try:
            if selected == "Custom IP / Range / CIDR...":
                raw_input = self.custom_entry.get().strip()
                if not raw_input:
                    messagebox.showwarning("Input Error", "Please specify a target IP, range, or CIDR block.")
                    return
                hosts = parse_custom_range(raw_input)
            else:
                idx = self.adapter_combo.current()
                hosts = list(self.adapters[idx]['network'].hosts())
        except Exception as e:
            messagebox.showerror("Parsing Error", f"Failed to parse target network range: {e}")
            return

        if not hosts:
            messagebox.showwarning("Target Error", "No valid target host IP addresses generated.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.cancel_event.clear()
        self.is_scan_running = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.set_status("Initializing native multi-stage network scanner...", status_type="running")

        mode = self.mode_var.get()

        threading.Thread(
            target=self.run_scan,
            args=(hosts, mode),
            daemon=True
        ).start()

    def run_scan(self, hosts, mode):
        try:
            results = scan_network_gui(
                hosts,
                discovery_mode=mode,
                status_callback=lambda msg: self.set_status(msg, status_type="running") if not self.cancel_event.is_set() else None,
                cancel_event=self.cancel_event
            )
            
            if self.cancel_event.is_set():
                self.scan_results = {}
                self.root.after(0, self.populate_results, {})
                self.set_status("Scan stopped mid-operation by user. Results cleared.", status_type="stopped")
            else:
                self.scan_results = results
                self.root.after(0, self.populate_results, results)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Failure", str(e)))
            self.set_status(f"Scan aborted due to error: {e}", status_type="stopped")
        finally:
            self.is_scan_running = False
            self.root.after(0, lambda: self.scan_btn.config(state="normal"))
            self.root.after(0, lambda: self.stop_btn.config(state="disabled"))

    def populate_results(self, results):
        self.apply_filter()
        if not results and not self.cancel_event.is_set():
            self.set_status("Scan completed. No active hosts discovered on subnet.", status_type="ready")
        elif results:
            self.set_status(f"Scan completed successfully. Discovered {len(results)} active host(s).", status_type="ready")

    # ============================================================
    # Live Search & Filter Logic
    # ============================================================

    def clear_filter(self):
        self.filter_query_var.set("")
        self.filter_field_var.set("All Fields")
        self.apply_filter()

    def apply_filter(self):
        query = self.filter_query_var.get().strip().lower()
        field_target = self.filter_field_var.get()

        # Clear active table rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.scan_results:
            return

        for ip in sorted(self.scan_results.keys(), key=ipaddress.ip_address):
            info = self.scan_results[ip]
            row_data = {
                "IP Address": ip,
                "MAC Address": info['mac'],
                "Vendor": info['vendor'],
                "Hostname": info['hostname'],
                "Open Ports": info['ports'],
                "Notes": info['notes']
            }

            match = False
            if not query:
                match = True
            elif field_target == "All Fields":
                match = any(query in str(val).lower() for val in [ip, info['mac'], info['vendor'], info['hostname'], info['method'], info['ports'], info['notes']])
            elif field_target in row_data:
                match = query in str(row_data[field_target]).lower()

            if match:
                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        ip,
                        info['mac'],
                        info['vendor'],
                        info['hostname'],
                        info['method'],
                        info['ports'],
                        info['notes']
                    )
                )

    def on_double_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return

        current_values = list(self.tree.item(item_id, "values"))
        ip_addr = current_values[0]
        mac_addr = current_values[1]
        current_note = current_values[6] if len(current_values) > 6 else ""

        new_note = simpledialog.askstring(
            "Edit Device Note",
            f"Enter custom note for {ip_addr} ({mac_addr}):",
            initialvalue=current_note,
            parent=self.root
        )

        if new_note is not None:
            cleaned_note = new_note.strip()
            current_values[6] = cleaned_note
            self.tree.item(item_id, values=current_values)
            
            if ip_addr in self.scan_results:
                self.scan_results[ip_addr]["notes"] = cleaned_note
            
            save_mac_mapping(mac_addr, ip_addr, cleaned_note)
            self.set_status(f"Saved note for {ip_addr} ({mac_addr}) to mapping reference file.", status_type="ready")

    def export_to_excel(self):
        if not self.scan_results and not self.tree.get_children():
            messagebox.showwarning("Export Warning", "No scan data available to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Spreadsheet", "*.xlsx"), ("CSV File", "*.csv")],
            title="Export Scan Results"
        )

        if not file_path:
            return

        headers = ["IP Address", "MAC Address", "Vendor / Manufacturer", "Hostname / Resolved Device", "Discovery Method", "Open Ports", "Notes"]
        rows = []

        for item_id in self.tree.get_children():
            rows.append(self.tree.item(item_id, "values"))

        try:
            if file_path.endswith(".xlsx"):
                import openpyxl
                from openpyxl.styles import Font, PatternFill, Alignment

                wb = openpyxl.Workbook()
                ws = wb.active
                ws.title = "Network Audit"

                ws.append(headers)
                header_fill = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
                header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")

                for cell in ws[1]:
                    cell.fill = header_fill
                    cell.font = header_font
                    cell.alignment = Alignment(horizontal="left", vertical="center")

                for row_data in rows:
                    ws.append(row_data)

                for col in ws.columns:
                    max_len = max(len(str(cell.value or '')) for cell in col)
                    col_letter = openpyxl.utils.get_column_letter(col[0].column)
                    ws.column_dimensions[col_letter].width = max(max_len + 3, 12)

                wb.save(file_path)

            else:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(rows)

            messagebox.showinfo("Export Successful", f"Scan results exported successfully to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write export file: {e}")


# ============================================================
# Main Program Launch Point
# ============================================================

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()