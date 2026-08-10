import ipaddress
import socket
import subprocess
import concurrent.futures
import re
import ctypes


# ============================================================
# Settings
# ============================================================

# Number of simultaneous ping processes.
# Keep this relatively low, especially when scanning over Wi-Fi.
MAX_WORKERS = 50


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

                # See if this network already exists.
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
# Scan network
# ============================================================

def scan_network(hosts):

    hosts = list(hosts)
    hosts_set = set(str(ip) for ip in hosts)

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
            executor.submit(ping, ip): ip
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
            print("Scan cancelled by user.")

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
    print("  Reading Windows ARP table...")

    arp_devices = get_arp_table()

    # Only keep ARP entries that belong to
    # the range we are actually scanning.
    filtered_arp = {
        ip: mac
        for ip, mac in arp_devices.items()
        if ip in hosts_set
    }

    print(
        f"  {len(filtered_arp)} ARP entries found"
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
    # Hostname discovery
    # --------------------------------------------------------

    print("Hostname discovery:")

    hostname_targets = list(devices.keys())

    total_hostnames = len(hostname_targets)
    completed_hostnames = 0

    if total_hostnames:

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=20
        ) as executor:

            futures = {
                executor.submit(
                    get_hostname,
                    ipaddress.ip_address(ip)
                ): ip
                for ip in hostname_targets
            }

            try:

                for future in concurrent.futures.as_completed(
                    futures
                ):

                    ip = futures[future]

                    completed_hostnames += 1

                    try:

                        hostname = future.result()

                        if hostname:
                            devices[ip]["hostname"] = hostname

                    except Exception:
                        pass

                    percentage = (
                        completed_hostnames /
                        total_hostnames
                    ) * 100

                    print(
                        f"\r  Resolving hostnames: "
                        f"{completed_hostnames}/"
                        f"{total_hostnames} "
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
        start_text, end_text = text.split("-", 1)

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
    print("1. Fast (Not Implemented Yet)")
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
            hosts
        )

    except KeyboardInterrupt:

        print()
        print()
        print("Scan cancelled by user.")
        return

    print()
    display_results(devices)


# ============================================================

if __name__ == "__main__":
    main()