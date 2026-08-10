import ipaddress
import socket
import subprocess
import concurrent.futures
import re
import time

from zeroconf import ServiceBrowser, Zeroconf


# ============================================================
# Settings
# ============================================================

# Number of simultaneous ping processes.
# Keep this relatively low, especially when scanning over Wi-Fi.

MAX_WORKERS = 50

# Number of simultaneous hostname lookups.

HOSTNAME_WORKERS = 20

# How long to listen for mDNS service types.

MDNS_SERVICE_DISCOVERY_TIME = 10

# How long to browse the discovered mDNS services.

MDNS_DEVICE_DISCOVERY_TIME = 10


# ============================================================
# Network detection
# ============================================================

def get_network_adapters():
    """
    Read Windows network configuration and return unique
    IPv4 networks with their adapter names.
    """

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

        # ----------------------------------------------------
        # Detect adapter header
        # ----------------------------------------------------

        adapter_match = re.match(
            r"^(.*adapter\s+)(.+):$",
            line,
            re.IGNORECASE
        )

        if adapter_match:

            current_adapter = adapter_match.group(2).strip()
            current_ip = None
            current_mask = None
            continue

        # ----------------------------------------------------
        # IPv4 address
        # ----------------------------------------------------

        if "IPv4 Address" in line:

            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)",
                line
            )

            if match:
                current_ip = match.group(1)

        # ----------------------------------------------------
        # Subnet mask
        # ----------------------------------------------------

        elif "Subnet Mask" in line:

            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)",
                line
            )

            if match:
                current_mask = match.group(1)

        # ----------------------------------------------------
        # Once we have IP + mask, calculate network
        # ----------------------------------------------------

        if (
            current_adapter
            and current_ip
            and current_mask
        ):

            try:

                interface = ipaddress.ip_interface(
                    f"{current_ip}/{current_mask}"
                )

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

                    if (
                        current_adapter
                        not in existing["adapters"]
                    ):
                        existing["adapters"].append(
                            current_adapter
                        )

                else:

                    networks.append(
                        {
                            "network": network,
                            "adapters": [
                                current_adapter
                            ],
                            "ips": [
                                current_ip
                            ]
                        }
                    )

                current_ip = None
                current_mask = None

            except ValueError:
                pass

    return networks


# ============================================================
# Ping
# ============================================================

def ping(ip):
    """Ping an IP address using Windows ping.exe."""

    result = subprocess.run(
        [
            "ping",
            "-n", "1",
            "-w", "300",
            str(ip)
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


# ============================================================
# Reverse DNS
# ============================================================

def get_hostname(ip):
    """Try reverse DNS lookup."""

    try:

        hostname = socket.gethostbyaddr(
            str(ip)
        )[0]

        return hostname

    except (socket.herror, socket.gaierror):

        return ""


# ============================================================
# ARP table
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
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+"
            r"([0-9a-fA-F-]{17})\s+"
            r"dynamic",
            line
        )

        if match:

            ip = match.group(1)

            mac = (
                match.group(2)
                .replace("-", ":")
                .upper()
            )

            arp_devices[ip] = mac

    return arp_devices


# ============================================================
# mDNS discovery
# ============================================================

def mdns_discover(hosts_set):
    """
    Discover mDNS devices without knowing their hostnames.

    This performs the same two-stage discovery that was
    successful in the standalone mDNS full-discovery test:

        1. Discover advertised service types.
        2. Browse every discovered service type.
        3. Collect hostname, IP address, and services.
        4. Filter the results to the requested scan range.

    hosts_set contains string IP addresses from the scan range.
    """

    print("mDNS discovery:")
    print("  Discovering advertised service types...")

    service_types = set()

    zeroconf = Zeroconf()

    # ========================================================
    # Stage 1 - Discover service types
    # ========================================================

    def service_type_handler(
        zeroconf,
        service_type,
        name,
        state_change
    ):

        if state_change.name == "Added":

            if (
                name.endswith("._tcp.local.")
                or
                name.endswith("._udp.local.")
            ):

                service_types.add(name)

    service_browser = ServiceBrowser(
        zeroconf,
        "_services._dns-sd._udp.local.",
        handlers=[service_type_handler]
    )

    try:

        time.sleep(
            MDNS_SERVICE_DISCOVERY_TIME
        )

    except KeyboardInterrupt:

        service_browser.cancel()
        zeroconf.close()
        raise

    service_browser.cancel()

    print(
        f"  {len(service_types)} "
        f"service types found"
    )

    if not service_types:

        zeroconf.close()

        print(
            "  No mDNS service types found."
        )

        return {}

    # ========================================================
    # Stage 2 - Browse all discovered service types
    # ========================================================

    print(
        "  Browsing discovered mDNS services..."
    )

    # IMPORTANT:
    # Collect ALL mDNS devices first.
    #
    # We intentionally do NOT filter by hosts_set while
    # callbacks are running. This makes the behavior match
    # the standalone discovery test and prevents a discovery
    # timing/filtering issue from hiding valid devices.

    all_mdns_devices = {}

    browsers = []

    def service_handler(
        zeroconf,
        service_type,
        name,
        state_change
    ):

        if state_change.name != "Added":
            return

        try:

            info = zeroconf.get_service_info(
                service_type,
                name,
                timeout=3000
            )

            if not info:
                return

            hostname = info.server

            if not hostname:
                return

            # Make sure the hostname is displayed as
            # a normal .local hostname.
            hostname = hostname.rstrip(".")

            addresses = info.parsed_addresses()

            for address in addresses:

                # We are interested in IPv4 for the
                # current scanner results.
                if ":" in address:
                    continue

                # Ignore unusable addresses.
                if not address:
                    continue

                if address not in all_mdns_devices:

                    all_mdns_devices[address] = {
                        "hostname": hostname,
                        "services": set()
                    }

                # Keep all services advertised by
                # this device.
                all_mdns_devices[address][
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

    # Give the service browsers enough time to receive
    # responses. The standalone test that successfully
    # found mx-test.local used 10 seconds.
    try:

        time.sleep(
            MDNS_DEVICE_DISCOVERY_TIME
        )

    except KeyboardInterrupt:

        for browser in browsers:
            browser.cancel()

        zeroconf.close()
        raise

    # Stop all browsers.
    for browser in browsers:
        browser.cancel()

    zeroconf.close()

    # ========================================================
    # Diagnostic information
    # ========================================================

    print(
        f"  {len(all_mdns_devices)} "
        f"mDNS devices discovered"
    )

    # ========================================================
    # Filter to the requested scan range
    # ========================================================

    mdns_devices = {}

    for ip, mdns_info in all_mdns_devices.items():

        if ip in hosts_set:

            mdns_devices[ip] = mdns_info

    print(
        f"  {len(mdns_devices)} "
        f"mDNS devices found in scan range"
    )

    # --------------------------------------------------------
    # Temporary diagnostic output
    # --------------------------------------------------------
    #
    # This is intentionally useful while we're developing
    # the scanner. It lets us see whether mDNS discovered
    # mx-test but the scan-range filtering removed it.

    if all_mdns_devices:

        print()
        print("  All mDNS devices discovered:")

        for ip in sorted(
            all_mdns_devices,
            key=lambda value: tuple(
                int(part)
                for part in value.split(".")
            )
        ):

            hostname = all_mdns_devices[ip][
                "hostname"
            ]

            print(
                f"    {ip:<17} "
                f"{hostname}"
            )

        print()

    return mdns_devices


# ============================================================
# Scan network
# ============================================================

def scan_network(
    hosts,
    discovery_mode="fast"
):

    hosts = list(hosts)

    hosts_set = set(
        str(ip)
        for ip in hosts
    )

    devices = {}

    total = len(hosts)
    completed = 0

    # --------------------------------------------------------
    # Ping scan
    # --------------------------------------------------------

    print()
    print(
        f"Ping scan using {MAX_WORKERS} "
        f"simultaneous workers:"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                ping,
                ip
            ): ip
            for ip in hosts
        }

        try:

            for future in concurrent.futures.as_completed(
                futures
            ):

                ip = futures[future]

                completed += 1

                try:

                    if future.result():

                        devices[str(ip)] = {
                            "hostname": "",
                            "mac": "",
                            "method": "Ping"
                        }

                except Exception:
                    pass

                percentage = (
                    completed / total
                ) * 100

                print(
                    f"\r  {completed}/{total} "
                    f"({percentage:5.1f}%) "
                    f"addresses scanned",
                    end="",
                    flush=True
                )

        except KeyboardInterrupt:

            print()
            print()
            print(
                "Scan cancelled by user."
            )

            executor.shutdown(
                wait=False,
                cancel_futures=True
            )

            return devices

    print()
    print()

    # --------------------------------------------------------
    # ARP discovery
    # --------------------------------------------------------

    print("ARP discovery:")
    print(
        "  Reading Windows ARP table..."
    )

    arp_devices = get_arp_table()

    filtered_arp = {
        ip: mac
        for ip, mac in arp_devices.items()
        if ip in hosts_set
    }

    print(
        f"  {len(filtered_arp)} "
        f"ARP entries found"
    )

    total_arp = len(filtered_arp)
    completed_arp = 0

    for ip, mac in filtered_arp.items():

        completed_arp += 1

        if ip not in devices:

            devices[ip] = {
                "hostname": "",
                "mac": mac,
                "method": "ARP"
            }

        else:

            devices[ip]["mac"] = mac
            devices[ip]["method"] = "Ping + ARP"

        percentage = (
            completed_arp / total_arp
        ) * 100 if total_arp else 100

        print(
            f"\r  Processing ARP entries: "
            f"{completed_arp}/{total_arp} "
            f"({percentage:5.1f}%)",
            end="",
            flush=True
        )

    print()
    print()

    # --------------------------------------------------------
    # mDNS discovery
    # --------------------------------------------------------

    if discovery_mode == "thorough":

        try:

            mdns_devices = mdns_discover(
                hosts_set
            )

            # ----------------------------------------------
            # Merge mDNS results into devices
            # ----------------------------------------------

            for ip, mdns_info in mdns_devices.items():

                hostname = mdns_info[
                    "hostname"
                ]

                if ip not in devices:

                    devices[ip] = {
                        "hostname": hostname,
                        "mac": "",
                        "method": "mDNS"
                    }

                else:

                    if (
                        not devices[ip]["hostname"]
                    ):
                        devices[ip][
                            "hostname"
                        ] = hostname

                    existing_method = devices[
                        ip
                    ]["method"]

                    if "mDNS" not in existing_method:

                        devices[ip][
                            "method"
                        ] = (
                            existing_method
                            + " + mDNS"
                        )

        except KeyboardInterrupt:

            print()
            print()
            print(
                "mDNS discovery "
                "cancelled by user."
            )

        print()
        print()

    # --------------------------------------------------------
    # Hostname discovery
    # --------------------------------------------------------

    print("Hostname discovery:")

    hostname_targets = list(
        devices.keys()
    )

    total_hostnames = len(
        hostname_targets
    )

    completed_hostnames = 0

    if total_hostnames:

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=HOSTNAME_WORKERS
        ) as executor:

            futures = {}

            for ip in hostname_targets:

                # If mDNS already gave us a hostname,
                # don't waste time performing reverse DNS
                # on that address.

                if devices[ip]["hostname"]:
                    continue

                futures[
                    executor.submit(
                        get_hostname,
                        ipaddress.ip_address(ip)
                    )
                ] = ip

            total_dns_lookups = len(
                futures
            )

            if total_dns_lookups:

                try:

                    for future in concurrent.futures.as_completed(
                        futures
                    ):

                        ip = futures[future]

                        completed_hostnames += 1

                        try:

                            hostname = future.result()

                            if hostname:

                                devices[ip][
                                    "hostname"
                                ] = hostname

                        except Exception:
                            pass

                        percentage = (
                            completed_hostnames
                            / total_dns_lookups
                        ) * 100

                        print(
                            f"\r  Resolving hostnames: "
                            f"{completed_hostnames}/"
                            f"{total_dns_lookups} "
                            f"({percentage:5.1f}%)",
                            end="",
                            flush=True
                        )

                except KeyboardInterrupt:

                    print()
                    print()
                    print(
                        "Hostname discovery "
                        "cancelled by user."
                    )

            else:

                print(
                    "  All devices already have "
                    "hostnames."
                )

    print()
    print()

    # --------------------------------------------------------
    # Return results
    # --------------------------------------------------------

    return devices


# ============================================================
# Display results
# ============================================================

def display_results(devices):

    print("Building results...")
    print()

    print(
        f"{'IP Address':<17}"
        f"{'Hostname':<35}"
        f"{'MAC Address':<20}"
        f"Discovery"
    )

    print("-" * 90)

    for ip in sorted(
        devices,
        key=ipaddress.ip_address
    ):

        device = devices[ip]

        print(
            f"{ip:<17}"
            f"{device['hostname']:<35}"
            f"{device['mac']:<20}"
            f"{device['method']}"
        )

    print()
    print("--------------------------------")
    print(
        f"Devices found: {len(devices)}"
    )
    print("--------------------------------")


# ============================================================
# Parse scan range
# ============================================================

def parse_scan_range(text):
    """
    Accept:

    192.168.1.0/24
    192.168.1.65-192.168.1.67
    192.168.1.66
    """

    text = text.strip()

    # CIDR notation

    if "/" in text:

        return list(
            ipaddress.ip_network(
                text,
                strict=False
            ).hosts()
        )

    # Explicit start-end range

    if "-" in text:

        start_text, end_text = text.split(
            "-",
            1
        )

        start = ipaddress.ip_address(
            start_text.strip()
        )

        end = ipaddress.ip_address(
            end_text.strip()
        )

        if start.version != end.version:

            raise ValueError(
                "Start and end addresses must use "
                "the same IP version."
            )

        if int(end) < int(start):

            raise ValueError(
                "End address must be greater than "
                "or equal to start address."
            )

        return [
            ipaddress.ip_address(value)
            for value in range(
                int(start),
                int(end) + 1
            )
        ]

    # Single IP

    return [
        ipaddress.ip_address(text)
    ]


# ============================================================
# Main
# ============================================================

def main():

    print()
    print("================================")
    print("       Network Scanner")
    print("================================")
    print()

    # --------------------------------------------------------
    # Load previous scan
    # --------------------------------------------------------

    last_scan_file = "last_scan.txt"
    previous_scan = None

    try:

        with open(
            last_scan_file,
            "r",
            encoding="utf-8"
        ) as file:

            previous_scan = file.read().strip()

    except FileNotFoundError:

        pass

    # --------------------------------------------------------
    # Detect networks
    # --------------------------------------------------------

    networks = get_network_adapters()

    if networks:

        print("Detected networks:")
        print()

        for number, network_info in enumerate(
            networks,
            start=1
        ):

            adapters = ", ".join(
                network_info["adapters"]
            )

            ips = ", ".join(
                network_info["ips"]
            )

            print(
                f"{number}. "
                f"{adapters:<35} "
                f"{network_info['network']}"
            )

            print(
                f"   Local IP: {ips}"
            )

        print()

    else:

        print(
            "No IPv4 networks were automatically "
            "detected."
        )

        print()

    # --------------------------------------------------------
    # Main menu
    # --------------------------------------------------------

    print("P. Previous scan")
    print("M. Enter an IP range manually")
    print("Q. Quit")
    print()

    choice = input(
        "Select a network, P, M, or Q: "
    ).strip()

    # --------------------------------------------------------
    # Quit
    # --------------------------------------------------------

    if choice.lower() == "q":

        print()
        print("Goodbye.")
        return

    # --------------------------------------------------------
    # Previous scan
    # --------------------------------------------------------

    if choice.lower() == "p":

        if not previous_scan:

            print()
            print(
                "No previous scan range has been saved."
            )
            return

        range_text = previous_scan

        print()
        print(
            f"Previous scan: {range_text}"
        )

        try:

            hosts = parse_scan_range(
                range_text
            )

        except ValueError as error:

            print()
            print(
                f"Saved range is invalid: {error}"
            )

            return

        scan_description = range_text

    # --------------------------------------------------------
    # Manual scan
    # --------------------------------------------------------

    elif choice.lower() == "m":

        print()
        print("Enter a scan range.")
        print()
        print("Examples:")
        print("  192.168.1.0/24")
        print("  10.40.61.65-10.40.61.67")
        print("  10.40.61.66")
        print()

        range_text = input(
            "Range: "
        ).strip()

        try:

            hosts = parse_scan_range(
                range_text
            )

        except ValueError as error:

            print()
            print(
                f"Invalid range: {error}"
            )

            return

        scan_description = range_text

    # --------------------------------------------------------
    # Automatically detected network
    # --------------------------------------------------------

    else:

        try:

            number = int(choice)

            if (
                number < 1
                or number > len(networks)
            ):

                raise ValueError

            subnet = networks[
                number - 1
            ]["network"]

            hosts = list(
                subnet.hosts()
            )

            scan_description = str(
                subnet
            )

            range_text = scan_description

        except (ValueError, IndexError):

            print()
            print("Invalid selection.")
            return

    # --------------------------------------------------------
    # Save range for next time
    # --------------------------------------------------------

    try:

        with open(
            last_scan_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                scan_description
            )

    except OSError:

        pass

    # --------------------------------------------------------
    # Discovery mode
    # --------------------------------------------------------

    print()
    print("Discovery mode:")
    print()
    print("1. Fast")
    print("2. Thorough")
    print("Q. Cancel")
    print()

    discovery_choice = input(
        "Select discovery mode [1]: "
    ).strip()

    if discovery_choice.lower() == "q":

        print()
        print("Scan cancelled.")
        return

    elif discovery_choice == "2":

        discovery_mode = "thorough"

    else:

        discovery_mode = "fast"

    # --------------------------------------------------------
    # Start scan
    # --------------------------------------------------------

    print()
    print(
        f"Scanning {scan_description}..."
    )

    print(
        f"Discovery mode: "
        f"{discovery_mode.capitalize()}"
    )

    print()

    try:

        devices = scan_network(
            hosts,
            discovery_mode
        )

    except KeyboardInterrupt:

        print()
        print()
        print("Scan cancelled by user.")
        return

    print()
    display_results(devices)


# ============================================================
# Program entry point
# ============================================================

if __name__ == "__main__":
    main()