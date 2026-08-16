import sys
import subprocess

# ============================================================
# Auto-Install Missing Dependencies
# ============================================================

REQUIRED_PACKAGES = {
    "zeroconf": "zeroconf",
    "scapy": "scapy",
    "mac_vendor_lookup": "mac-vendor-lookup"
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

# Execute package installation before importing
install_missing_packages()

import ipaddress
import socket
import concurrent.futures
import re
import time
import ctypes
from collections import Counter

from zeroconf import ServiceBrowser, Zeroconf
import scapy.all as scapy
from mac_vendor_lookup import MacLookup

# Initialize live MAC lookup engine
try:
    mac_lookup_engine = MacLookup()
    # Asynchronously update vendor database in the background if needed
except Exception:
    mac_lookup_engine = None


# ============================================================
# Settings
# ============================================================

MAX_WORKERS = 50
HOSTNAME_WORKERS = 20
PORT_SCAN_WORKERS = 20
MDNS_SERVICE_DISCOVERY_TIME = 10
MDNS_DEVICE_DISCOVERY_TIME = 10

COMMON_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 8080]


# ============================================================
# Native & Scapy Layer 2 / Layer 3 Discovery
# ============================================================

def send_arp_probe(ip_str):
    """
    Sends a direct Layer 2 ARP request via Windows iphlpapi.dll with fallback to Scapy.
    """
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

    # Scapy ARP Fallback
    try:
        arp_request = scapy.ARP(pdst=ip_str)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=0.8, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc.upper()
    except Exception:
        pass

    return None


# ============================================================
# Network Detection & Range Parsing
# ============================================================

def get_network_adapters():
    """Read Windows network configuration and return unique IPv4 networks."""
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
    """Parse custom CIDR, hyphenated range, or single IP."""
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

def get_scapy_netbios(ip):
    """Query NetBIOS via Scapy over Raw UDP 137."""
    try:
        nbns_req = scapy.IP(dst=str(ip))/scapy.UDP(dport=137)/scapy.NBNSQueryRequest(
            QUESTION_NAME=b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            QUESTION_TYPE="NBSTAT"
        )
        response = scapy.sr1(nbns_req, timeout=0.6, verbose=False)
        if response and response.haslayer(scapy.NBNSNodeStatusResponse):
            names = response[scapy.NBNSNodeStatusResponse].ADDR_ENTRY
            for name_entry in names:
                name = name_entry.RR_NAME.strip().decode('ascii', errors='ignore')
                if name and not name.startswith('WORKGROUP'):
                    return name
    except Exception:
        pass
    return None


def get_netbios_name(ip):
    """Attempt NetBIOS hostname lookup using Windows nbtstat."""
    try:
        result = subprocess.run(
            ["nbtstat", "-A", str(ip)],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=2.0
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

    except (
        subprocess.TimeoutExpired,
        subprocess.SubprocessError,
        OSError
    ):
        pass

    return None

def resolve_host_info(ip):
    """Try Reverse DNS lookup first, falling back to NetBIOS."""
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
    """Live OUI Vendor Lookup using mac_vendor_lookup."""
    if not mac or mac == "N/A" or not mac_lookup_engine:
        return ""
    try:
        vendor = mac_lookup_engine.lookup(mac)
        return vendor.strip()
    except Exception:
        pass
    return ""


def infer_smart_hostname(mac, open_ports_str):
    """Deduce device class when DNS, mDNS, NetBIOS, and OUI yield no match."""
    is_randomized_mac = False
    if mac and len(mac) >= 2:
        second_char = mac[1].upper()
        if second_char in ['2', '6', 'A', 'E']:
            is_randomized_mac = True

    ports = [p.strip() for p in open_ports_str.split(",") if p.strip().isdigit()]
    
    if "80" in ports or "443" in ports or "8080" in ports:
        return "[Web/Network Appliance]"
    if "135" in ports or "139" in ports or "445" in ports or "3389" in ports:
        return "[Windows Device]"
    if "22" in ports:
        return "[Linux/SSH Host]"
    if "21" in ports or "23" in ports:
        return "[Legacy Network Device]"
    
    if is_randomized_mac:
        return "[Mobile/Private MAC Device]"

    return "[Unknown Host]"


# ============================================================
# ARP Table & Gateway Resolution
# ============================================================

def get_arp_table():
    """Read the Windows ARP table."""
    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True
    )

    arp_devices = {}
    for line in result.stdout.splitlines():
        match = re.search(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+dynamic",
            line
        )
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            arp_devices[ip] = mac

    return arp_devices


def get_default_gateway_mac():
    """Find default gateway IP and look up its MAC address in ARP table."""
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
# mDNS Discovery
# ============================================================

def mdns_discover(hosts_set):
    """Discover mDNS devices across the local network."""

    print("mDNS discovery:")
    print("  Discovering advertised service types...")

    service_types = set()

    # --------------------------------------------------------
    # Service-type discovery
    #
    # We give mDNS 10 seconds initially. If absolutely
    # nothing is received, perform one additional attempt.
    #
    # This helps with devices that don't answer immediately
    # when the scanner starts listening.
    # --------------------------------------------------------

    def discover_service_types():

        discovered = set()
        zeroconf = Zeroconf()

        def service_type_handler(
            zeroconf=None,
            service_type=None,
            name=None,
            state_change=None,
            **kwargs
        ):

            if name is None or state_change is None:
                return

            if getattr(
                state_change,
                "name",
                ""
            ) != "Added":
                return

            if (
                name.endswith("._tcp.local.")
                or name.endswith("._udp.local.")
            ):

                discovered.add(name)

        browser = ServiceBrowser(
            zeroconf,
            "_services._dns-sd._udp.local.",
            handlers=[service_type_handler]
        )

        try:

            time.sleep(
                MDNS_SERVICE_DISCOVERY_TIME
            )

        except KeyboardInterrupt:

            browser.cancel()
            zeroconf.close()
            raise

        browser.cancel()
        zeroconf.close()

        return discovered

    # --------------------------------------------------------
    # First attempt
    # --------------------------------------------------------

    service_types.update(
        discover_service_types()
    )

    print(
        f"  {len(service_types)} "
        f"service types found"
    )

    # --------------------------------------------------------
    # Retry only if absolutely nothing was received.
    #
    # We don't want to make normal scans unnecessarily slow.
    # --------------------------------------------------------

    if not service_types:

        print(
            "  No service types received."
        )

        print(
            "  Retrying mDNS service discovery..."
        )

        service_types.update(
            discover_service_types()
        )

        print(
            f"  Retry found {len(service_types)} "
            f"service types"
        )

    if not service_types:

        print(
            "  No mDNS service types found."
        )

        return {}

    # --------------------------------------------------------
    # Browse the services we discovered
    # --------------------------------------------------------

    print(
        "  Browsing discovered mDNS services..."
    )

    mdns_devices = {}
    browsers = []

    zeroconf = Zeroconf()

    def service_handler(
        zeroconf=None,
        service_type=None,
        name=None,
        state_change=None,
        **kwargs
    ):

        if (
            name is None
            or service_type is None
            or state_change is None
        ):
            return

        if getattr(
            state_change,
            "name",
            ""
        ) != "Added":
            return

        try:

            info = zeroconf.get_service_info(
                service_type,
                name,
                timeout=2000
            )

            if not info or not info.server:
                return

            hostname = info.server
            addresses = info.parsed_addresses()

            for address in addresses:

                try:

                    parsed_ip = ipaddress.ip_address(
                        address
                    )

                    # We are currently using IPv4 scan ranges.
                    if parsed_ip.version != 4:
                        continue

                except ValueError:

                    continue

                # Only retain devices belonging to the
                # requested scan range.
                if address not in hosts_set:
                    continue

                if address not in mdns_devices:

                    mdns_devices[address] = {
                        "hostname": hostname,
                        "services": set()
                    }

                elif not mdns_devices[address]["hostname"]:

                    mdns_devices[address][
                        "hostname"
                    ] = hostname

                mdns_devices[address][
                    "services"
                ].add(service_type)

        except Exception:
            pass

    # --------------------------------------------------------
    # Create a browser for every discovered service type.
    # --------------------------------------------------------

    for service_type in sorted(service_types):

        try:

            browser = ServiceBrowser(
                zeroconf,
                service_type,
                handlers=[service_handler]
            )

            browsers.append(browser)

        except Exception:
            pass

    # --------------------------------------------------------
    # Allow devices time to respond.
    # --------------------------------------------------------

    try:

        time.sleep(
            MDNS_DEVICE_DISCOVERY_TIME
        )

    except KeyboardInterrupt:

        for browser in browsers:
            browser.cancel()

        zeroconf.close()
        raise

    # --------------------------------------------------------
    # Stop browsing.
    # --------------------------------------------------------

    for browser in browsers:
        browser.cancel()

    zeroconf.close()

    # --------------------------------------------------------
    # Display results.
    # --------------------------------------------------------

    print()

    if mdns_devices:

        print(
            "  All mDNS devices discovered:"
        )

        for ip in sorted(
            mdns_devices,
            key=ipaddress.ip_address
        ):

            hostname = mdns_devices[ip][
                "hostname"
            ]

            print(
                f"    {ip:<17} "
                f"{hostname}"
            )

            services = sorted(
                mdns_devices[ip]["services"]
            )

            print(
                f"      Services: "
                f"{', '.join(services)}"
            )

    else:

        print(
            "  No mDNS devices found."
        )

    print()

    print(
        f"  {len(mdns_devices)} "
        f"mDNS devices found in scan range"
    )

    return mdns_devices

# ============================================================
# Port Scanning Subsystem
# ============================================================

def scan_single_port(ip, port):
    """Attempt TCP socket connection to a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            if s.connect_ex((str(ip), port)) == 0:
                return port
    except Exception:
        pass
    return None


def scan_open_ports(ip):
    """Scan common TCP ports concurrently for a verified host."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = [executor.submit(scan_single_port, ip, port) for port in COMMON_PORTS]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
    
    open_ports.sort()
    return ", ".join(str(p) for p in open_ports) if open_ports else "None"


# ============================================================
# Main Network Scanner
# ============================================================

def scan_network(hosts, discovery_mode="fast"):
    hosts = list(hosts)
    hosts_set = set(str(ip) for ip in hosts)
    
    total = len(hosts)
    completed = 0
    direct_arp_hits = {}

    # 1. Native & Scapy Direct ARP Discovery
    print()
    print(f"Direct Layer-2 ARP Discovery using {MAX_WORKERS} workers:")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(send_arp_probe, str(ip)): str(ip) for ip in hosts}
        try:
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                completed += 1

                try:
                    mac = future.result()
                    if mac:
                        direct_arp_hits[ip] = mac
                except Exception:
                    pass

                percentage = (completed / total) * 100
                print(
                    f"\r  {completed}/{total} ({percentage:5.1f}%) addresses probed",
                    end="",
                    flush=True
                )

        except KeyboardInterrupt:
            print("\n\nScan cancelled by user.")
            executor.shutdown(wait=False, cancel_futures=True)
            return {}

    print("\n")

    # 2. System ARP Table Backup & Proxy Filtering
    print("ARP discovery:")
    print("  Reading Windows ARP table...")
    arp_table = get_arp_table()
    
    combined_arp = {**arp_table, **direct_arp_hits}
    subnet_arp = {ip: mac for ip, mac in combined_arp.items() if ip in hosts_set}

    mac_counts = Counter(subnet_arp.values())
    proxy_macs = set()

    gateway_mac = get_default_gateway_mac()
    if gateway_mac:
        proxy_macs.add(gateway_mac)

    for mac, count in mac_counts.items():
        if count >= 3:
            proxy_macs.add(mac)

    if proxy_macs:
        for pm in proxy_macs:
            print(f"  Filtering Proxy/Gateway MAC: {pm}")

    # 3. mDNS Discovery
    mdns_devices = {}
    if discovery_mode == "thorough":
        mdns_devices = mdns_discover(hosts_set)

    # 4. Hostname & NetBIOS Discovery
    print("Hostname discovery:")
    print("  Resolving hostnames and NetBIOS info...")

    # ------------------------------------------------------------
    # Only perform hostname/NetBIOS lookups against devices that
    # have survived ARP discovery or were independently discovered
    # through mDNS.
    #
    # ARP-discovered devices have a real Layer-2 MAC address.
    # mDNS-discovered devices may not have appeared in the ARP
    # table, so they remain valid candidates as well.
    # ------------------------------------------------------------

    candidate_ips = sorted(
        set(subnet_arp.keys()).union(mdns_devices.keys()),
        key=ipaddress.ip_address
    )

    resolved_hostnames = {}

    # ------------------------------------------------------------
    # Resolve hostname information.
    #
    # resolve_host_info() handles the individual lookup methods.
    # We are deliberately NOT sending every address in the
    # requested range to NetBIOS.
    # ------------------------------------------------------------

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=HOSTNAME_WORKERS
    ) as executor:

        futures = {}

        for ip in candidate_ips:

            # If mDNS already supplied a hostname, don't waste
            # time trying to resolve it again.
            mdns_hostname = (
                mdns_devices
                .get(ip, {})
                .get("hostname", "")
            )

            if mdns_hostname:
                continue

            # Only attempt hostname/NetBIOS resolution against
            # an address with a real ARP discovery result.
            #
            # This prevents NetBIOS from attempting lookups against
            # ghost/proxy addresses.
            if ip in subnet_arp:
                futures[
                    executor.submit(
                        resolve_host_info,
                        ip
                    )
                ] = ip

        completed = 0
        total = len(futures)

        for future in concurrent.futures.as_completed(futures):

            ip = futures[future]
            completed += 1

            try:

                name = future.result()

                if name:
                    resolved_hostnames[ip] = name

            except Exception:
                pass

            if total:

                print(
                    f"\r  Resolving hostnames and NetBIOS: "
                    f"{completed}/{total} "
                    f"({completed / total * 100:5.1f}%)",
                    end="",
                    flush=True
                )

    print()
    print()

    # ------------------------------------------------------------
    # 5. Filter Ghost Entries, Scan Ports, and Construct Results
    # ------------------------------------------------------------

    devices = {}
    active_target_ips = []

    for ip in candidate_ips:

        mac = subnet_arp.get(ip, "")

        dns_netbios_name = (
            resolved_hostnames.get(ip, "")
        )

        mdns_name = (
            mdns_devices
            .get(ip, {})
            .get("hostname", "")
        )

        # mDNS gets priority because it is the discovery method
        # that directly gave us the hostname.
        hostname = (
            mdns_name
            or dns_netbios_name
        )

        has_mdns = ip in mdns_devices
        is_arp_hit = ip in subnet_arp
        is_proxy_mac = mac in proxy_macs

        # --------------------------------------------------------
        # Ghost/proxy filtering
        #
        # A proxy MAC by itself does NOT prove that this is a real
        # device. Keep it only if another discovery mechanism
        # independently identifies the host.
        # --------------------------------------------------------

        if (
            is_proxy_mac
            and not has_mdns
            and not hostname
        ):
            continue

        # --------------------------------------------------------
        # A device must have at least one independent discovery
        # result: ARP, mDNS, or a hostname.
        # --------------------------------------------------------

        if (
            not is_arp_hit
            and not has_mdns
            and not hostname
        ):
            continue

        active_target_ips.append(ip)

    print("Port discovery:")
    print(f"  Scanning common TCP ports across {len(active_target_ips)} active host(s)...")
    scanned_ports = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as executor:
        futures = {executor.submit(scan_open_ports, ip): ip for ip in active_target_ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                scanned_ports[ip] = future.result()
            except Exception:
                scanned_ports[ip] = "None"

    for ip in active_target_ips:
        mac = subnet_arp.get(ip, "")
        dns_netbios_name = resolved_hostnames.get(ip, "")
        mdns_name = mdns_devices.get(ip, {}).get("hostname", "")
        open_ports = scanned_ports.get(ip, "None")
        
        hostname = mdns_name or dns_netbios_name
        has_mdns = ip in mdns_devices
        is_proxy_mac = mac in proxy_macs

        # 1. Live MAC Vendor Lookup
        if not hostname and mac:
            vendor = get_vendor_by_mac(mac)
            if vendor:
                hostname = f"[{vendor}]"

        # 2. Smart Hostname Fallback Inference
        if not hostname:
            hostname = infer_smart_hostname(mac, open_ports)

        methods = []
        if ip in direct_arp_hits:
            methods.append("ARP Direct")
        elif mac and not is_proxy_mac:
            methods.append("ARP Table")
        if has_mdns:
            methods.append("mDNS")

        devices[ip] = {
            "hostname": hostname,
            "mac": mac if not is_proxy_mac else "Gateway (Proxy)",
            "method": " + ".join(methods) if methods else "DNS/NetBIOS Only",
            "ports": open_ports,
            "mdns_services": list(mdns_devices.get(ip, {}).get("services", []))
        }

    return devices


# ============================================================
# Main Execution Loop
# ============================================================

def main():
    print("=" * 60)
    print("              mDNS & Network Scanner")
    print("=" * 60)

    adapters = get_network_adapters()
    print("\nSelect target network or range:")
    
    idx = 1
    for net_info in adapters:
        net_str = str(net_info['network'])
        ip_str = ", ".join(net_info['ips'])
        adapter_str = ", ".join(net_info['adapters'])
        print(f"  [{idx}] {net_str:<18} ({ip_str}) - {adapter_str}")
        idx += 1

    print(f"  [{idx}] Custom IP / Range / Subnet (e.g., 10.40.61.26-10.40.61.27)")

    user_choice = input(f"\nEnter choice [1]: ").strip() or "1"

    try:
        choice_num = int(user_choice)
        if 1 <= choice_num <= len(adapters):
            hosts = list(adapters[choice_num - 1]['network'].hosts())
        elif choice_num == idx:
            raw_range = input("\nEnter IP, range, or CIDR (e.g. 10.40.61.26-27): ").strip()
            hosts = parse_custom_range(raw_range)
        else:
            print("Invalid choice.")
            return
    except ValueError:
        try:
            hosts = parse_custom_range(user_choice)
        except Exception as e:
            print(f"Invalid IP range input: {e}")
            return

    if not hosts:
        print("No valid target IP addresses specified.")
        return

    print("\nSelect Discovery Mode:")
    print("  [1] Fast Scan (ARP Probe + Reverse DNS + NetBIOS + Ports)")
    print("  [2] Thorough Scan (Fast Scan + Active mDNS Browse)")

    mode_choice = input("\nEnter choice [1]: ").strip()
    discovery_mode = "thorough" if mode_choice == "2" else "fast"

    print(f"\nStarting {discovery_mode.upper()} scan on {len(hosts)} target host(s)...")

    results = scan_network(hosts, discovery_mode=discovery_mode)

    print("\n" + "=" * 115)
    print(f"{'IP Address':<14} {'MAC Address':<20} {'Hostname / Vendor':<30} {'Discovery Method':<20} {'Ports Open':<22}")
    print("=" * 115)

    if not results:
        print("No active devices discovered.")
    else:
        for ip in sorted(results.keys(), key=ipaddress.ip_address):
            info = results[ip]
            print(f"{ip:<14} {info['mac']:<20} {info['hostname']:<30} {info['method']:<20} {info['ports']:<18}")

    print("=" * 115)


if __name__ == "__main__":
    main()