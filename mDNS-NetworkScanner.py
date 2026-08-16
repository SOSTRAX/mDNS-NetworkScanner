import ipaddress
import json
import os
import socket
import subprocess
import sys
import concurrent.futures
import queue
import re
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

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

# Where per-device notes entered in the GUI are stored.

NOTES_FILE = os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)
    ),
    "device_notes.json"
)


# ============================================================
# Progress reporting
# ============================================================

def console_progress(text, transient=False):
    """Default progress reporter used by the console interface."""

    if transient:
        print(f"\r{text}", end="", flush=True)
    else:
        print(text)


def interruptible_sleep(seconds, cancel_event=None):
    """Sleep, but return early when a cancel event is set."""

    if cancel_event is None:
        time.sleep(seconds)
        return

    cancel_event.wait(seconds)


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

def mdns_discover(
    hosts_set,
    progress=None,
    cancel_event=None
):
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

    report = progress or console_progress

    report("mDNS discovery:")
    report("  Discovering advertised service types...")

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

        interruptible_sleep(
            MDNS_SERVICE_DISCOVERY_TIME,
            cancel_event
        )

    except KeyboardInterrupt:

        service_browser.cancel()
        zeroconf.close()
        raise

    service_browser.cancel()

    if cancel_event is not None and cancel_event.is_set():

        zeroconf.close()
        return {}

    report(
        f"  {len(service_types)} "
        f"service types found"
    )

    if not service_types:

        zeroconf.close()

        report(
            "  No mDNS service types found."
        )

        return {}

    # ========================================================
    # Stage 2 - Browse all discovered service types
    # ========================================================

    report(
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

        interruptible_sleep(
            MDNS_DEVICE_DISCOVERY_TIME,
            cancel_event
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

    report(
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

    report(
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

        report("")
        report("  All mDNS devices discovered:")

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

            report(
                f"    {ip:<17} "
                f"{hostname}"
            )

        report("")

    return mdns_devices


# ============================================================
# Scan network
# ============================================================

def scan_network(
    hosts,
    discovery_mode="fast",
    progress=None,
    cancel_event=None
):

    report = progress or console_progress

    def cancelled():
        return (
            cancel_event is not None
            and cancel_event.is_set()
        )

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

    report("")
    report(
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

                if cancelled():

                    executor.shutdown(
                        wait=False,
                        cancel_futures=True
                    )

                    return devices

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

                report(
                    f"  {completed}/{total} "
                    f"({percentage:5.1f}%) "
                    f"addresses scanned",
                    True
                )

        except KeyboardInterrupt:

            report("")
            report("")
            report(
                "Scan cancelled by user."
            )

            executor.shutdown(
                wait=False,
                cancel_futures=True
            )

            return devices

    report("")
    report("")

    if cancelled():
        return devices

    # --------------------------------------------------------
    # ARP discovery
    # --------------------------------------------------------

    report("ARP discovery:")
    report(
        "  Reading Windows ARP table..."
    )

    arp_devices = get_arp_table()

    filtered_arp = {
        ip: mac
        for ip, mac in arp_devices.items()
        if ip in hosts_set
    }

    report(
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

        report(
            f"  Processing ARP entries: "
            f"{completed_arp}/{total_arp} "
            f"({percentage:5.1f}%)",
            True
        )

    report("")
    report("")

    if cancelled():
        return devices

    # --------------------------------------------------------
    # mDNS discovery
    # --------------------------------------------------------

    if discovery_mode == "thorough":

        try:

            mdns_devices = mdns_discover(
                hosts_set,
                progress,
                cancel_event
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

            report("")
            report("")
            report(
                "mDNS discovery "
                "cancelled by user."
            )

        report("")
        report("")

    if cancelled():
        return devices

    # --------------------------------------------------------
    # Hostname discovery
    # --------------------------------------------------------

    report("Hostname discovery:")

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

                        if cancelled():

                            executor.shutdown(
                                wait=False,
                                cancel_futures=True
                            )

                            return devices

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

                        report(
                            f"  Resolving hostnames: "
                            f"{completed_hostnames}/"
                            f"{total_dns_lookups} "
                            f"({percentage:5.1f}%)",
                            True
                        )

                except KeyboardInterrupt:

                    report("")
                    report("")
                    report(
                        "Hostname discovery "
                        "cancelled by user."
                    )

            else:

                report(
                    "  All devices already have "
                    "hostnames."
                )

    report("")
    report("")

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
# Notes storage
# ============================================================

def note_key(ip, mac):
    """
    Key used to remember a note.

    A MAC address follows a device even when DHCP gives it
    a different address, so it is preferred over the IP.
    """

    if mac:
        return f"mac:{mac}"

    return f"ip:{ip}"


def load_notes():

    try:

        with open(
            NOTES_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            notes = json.load(file)

    except (OSError, ValueError):

        return {}

    if not isinstance(notes, dict):
        return {}

    return {
        str(key): str(value)
        for key, value in notes.items()
    }


def save_notes(notes):

    try:

        with open(
            NOTES_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                notes,
                file,
                indent=2,
                sort_keys=True
            )

    except OSError:

        pass


# ============================================================
# Graphical interface
# ============================================================

COLUMNS = (
    ("ip", "IP Address", 130),
    ("hostname", "Hostname", 260),
    ("mac", "MAC Address", 150),
    ("method", "Discovery", 160),
    ("note", "Note", 300)
)


class ScannerWindow:
    """Tkinter front end for the network scanner."""

    def __init__(self, root):

        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("1080x640")

        self.networks = get_network_adapters()
        self.notes = load_notes()

        self.messages = queue.Queue()
        self.cancel_event = None
        self.scan_thread = None
        self.note_editor = None

        self._build_controls()
        self._build_table()
        self._build_status()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.on_close
        )

        self.root.after(100, self._drain_messages)

    # --------------------------------------------------------
    # Layout
    # --------------------------------------------------------

    def _build_controls(self):

        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="x")

        ttk.Label(
            frame,
            text="Network:"
        ).grid(row=0, column=0, sticky="w")

        self.network_choice = ttk.Combobox(
            frame,
            state="readonly",
            width=55,
            values=[
                f"{', '.join(item['adapters'])} "
                f"({item['network']})"
                for item in self.networks
            ]
        )

        self.network_choice.grid(
            row=0,
            column=1,
            sticky="w",
            padx=(6, 20)
        )

        if self.networks:
            self.network_choice.current(0)

        self.network_choice.bind(
            "<<ComboboxSelected>>",
            self._on_network_selected
        )

        ttk.Label(
            frame,
            text="Range:"
        ).grid(row=0, column=2, sticky="w")

        self.range_value = tk.StringVar()

        ttk.Entry(
            frame,
            textvariable=self.range_value,
            width=28
        ).grid(
            row=0,
            column=3,
            sticky="w",
            padx=(6, 20)
        )

        self.mode_value = tk.StringVar(value="fast")

        ttk.Radiobutton(
            frame,
            text="Fast",
            value="fast",
            variable=self.mode_value
        ).grid(row=0, column=4, sticky="w")

        ttk.Radiobutton(
            frame,
            text="Thorough (mDNS)",
            value="thorough",
            variable=self.mode_value
        ).grid(row=0, column=5, sticky="w", padx=(6, 20))

        self.scan_button = ttk.Button(
            frame,
            text="Scan",
            command=self.start_scan
        )

        self.scan_button.grid(row=0, column=6, padx=(0, 6))

        self.cancel_button = ttk.Button(
            frame,
            text="Cancel",
            command=self.cancel_scan,
            state="disabled"
        )

        self.cancel_button.grid(row=0, column=7)

        self._on_network_selected()

    def _build_table(self):

        frame = ttk.Frame(self.root, padding=(10, 0))
        frame.pack(fill="both", expand=True)

        self.table = ttk.Treeview(
            frame,
            columns=[name for name, _, _ in COLUMNS],
            show="headings",
            selectmode="browse"
        )

        for name, heading, width in COLUMNS:

            self.table.heading(name, text=heading)
            self.table.column(name, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.table.bind("<Double-1>", self._begin_note_edit)
        self.table.bind("<Return>", self._begin_note_edit)

    def _build_status(self):

        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both")

        self.status_value = tk.StringVar(
            value="Double-click the Note column to describe a device."
        )

        ttk.Label(
            frame,
            textvariable=self.status_value
        ).pack(anchor="w")

        self.log = tk.Text(frame, height=8, wrap="none")
        self.log.configure(state="disabled")
        self.log.pack(fill="both", expand=True, pady=(6, 0))

    # --------------------------------------------------------
    # Controls
    # --------------------------------------------------------

    def _on_network_selected(self, event=None):

        index = self.network_choice.current()

        if 0 <= index < len(self.networks):

            self.range_value.set(
                str(self.networks[index]["network"])
            )

    def start_scan(self):

        if self.scan_thread and self.scan_thread.is_alive():
            return

        range_text = self.range_value.get().strip()

        if not range_text:

            messagebox.showerror(
                "Network Scanner",
                "Enter a range such as 192.168.1.0/24, "
                "192.168.1.10-192.168.1.20 or 192.168.1.10."
            )

            return

        try:

            hosts = parse_scan_range(range_text)

        except ValueError as error:

            messagebox.showerror(
                "Network Scanner",
                f"Invalid range: {error}"
            )

            return

        self._close_note_editor()
        self.table.delete(*self.table.get_children())

        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

        mode = self.mode_value.get()

        self.cancel_event = threading.Event()

        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")

        self.status_value.set(
            f"Scanning {range_text} ({mode})..."
        )

        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(hosts, mode, self.cancel_event),
            daemon=True
        )

        self.scan_thread.start()

    def cancel_scan(self):

        if self.cancel_event:

            self.cancel_event.set()

            self.status_value.set(
                "Cancelling scan..."
            )

    # --------------------------------------------------------
    # Worker thread
    # --------------------------------------------------------

    def _run_scan(self, hosts, mode, cancel_event):

        def progress(text, transient=False):

            self.messages.put(
                ("status" if transient else "log", text)
            )

        try:

            devices = scan_network(
                hosts,
                mode,
                progress,
                cancel_event
            )

            self.messages.put(("results", devices))

        except Exception as error:

            self.messages.put(("error", str(error)))

    def _drain_messages(self):

        try:

            while True:

                kind, payload = self.messages.get_nowait()

                if kind == "status":
                    self.status_value.set(payload)

                elif kind == "log":
                    self._append_log(payload)

                elif kind == "results":
                    self._show_results(payload)

                elif kind == "error":

                    self._finish_scan()

                    messagebox.showerror(
                        "Network Scanner",
                        f"Scan failed: {payload}"
                    )

        except queue.Empty:

            pass

        self.root.after(100, self._drain_messages)

    def _append_log(self, text):

        self.log.configure(state="normal")
        self.log.insert("end", f"{text}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    def _show_results(self, devices):

        for ip in sorted(devices, key=ipaddress.ip_address):

            device = devices[ip]

            note = self.notes.get(
                note_key(ip, device["mac"]),
                ""
            )

            self.table.insert(
                "",
                "end",
                values=(
                    ip,
                    device["hostname"],
                    device["mac"],
                    device["method"],
                    note
                )
            )

        cancelled = (
            self.cancel_event is not None
            and self.cancel_event.is_set()
        )

        self.status_value.set(
            f"{'Cancelled - ' if cancelled else ''}"
            f"Devices found: {len(devices)}"
        )

        self._finish_scan()

    def _finish_scan(self):

        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")

    # --------------------------------------------------------
    # Note editing
    # --------------------------------------------------------

    def _begin_note_edit(self, event):

        self._close_note_editor()

        row = self.table.focus()

        if event.type == tk.EventType.ButtonPress:

            row = self.table.identify_row(event.y)

            if self.table.identify_column(event.x) != "#5":
                return

        if not row:
            return

        box = self.table.bbox(row, "note")

        if not box:
            return

        x, y, width, height = box

        editor = ttk.Entry(self.table)
        editor.place(x=x, y=y, width=width, height=height)
        editor.insert(0, self.table.set(row, "note"))
        editor.select_range(0, "end")
        editor.focus_set()

        editor.bind(
            "<Return>",
            lambda _event: self._commit_note(row, editor)
        )

        editor.bind(
            "<FocusOut>",
            lambda _event: self._commit_note(row, editor)
        )

        editor.bind(
            "<Escape>",
            lambda _event: self._close_note_editor()
        )

        self.note_editor = editor

    def _commit_note(self, row, editor):

        if self.note_editor is not editor:
            return

        note = editor.get().strip()

        self.table.set(row, "note", note)

        key = note_key(
            self.table.set(row, "ip"),
            self.table.set(row, "mac")
        )

        if note:
            self.notes[key] = note
        else:
            self.notes.pop(key, None)

        save_notes(self.notes)

        self._close_note_editor()

        self.status_value.set(
            f"Note saved for {self.table.set(row, 'ip')}."
        )

    def _close_note_editor(self):

        if self.note_editor is not None:

            editor = self.note_editor
            self.note_editor = None
            editor.destroy()

    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    def on_close(self):

        if self.cancel_event:
            self.cancel_event.set()

        save_notes(self.notes)

        self.root.destroy()


def run_gui():

    root = tk.Tk()
    ScannerWindow(root)
    root.mainloop()


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

    if "--console" in sys.argv:
        main()
    else:
        run_gui()