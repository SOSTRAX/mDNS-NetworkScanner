# mDNS Network Scanner

mDNS Network Scanner is a Windows network discovery and device inventory tool for scanning active interfaces, IPv4 subnets, and custom range targets. It identifies responding hosts, resolves MAC addresses and vendor data, detects hostnames, audits common TCP ports, and saves custom notes tied to the device's MAC address so they persist and reload automatically across scans.

## What it does

- Detects active local IPv4 networks and available Windows adapters
- Scans a selected subnet, interface range, or custom target list
- Supports scoped targets like:
  - 192.168.1.0/24
  - 10.40.61.38-67
  - 10.40.61.38-10.40.61.67
  - 10.40.61.66
- Performs ICMP ping sweeps and Windows ARP probing
- Resolves hostnames and NetBIOS names when available
- Looks up vendor names using the device MAC address
- Audits common TCP ports for discovered devices
- Highlights newly found devices in green on rescan
- Saves per-device notes keyed to the MAC address so notes remain associated even when an IP address changes
- Supports sorting and filtering within the results grid
- Exports results to Excel or CSV

## Supported scan input formats

The scanner accepts the following range formats:

```text
192.168.1.0/24
10.40.61.38-67
10.40.61.38-10.40.61.67
10.40.61.66
```

## Notes and behavior

- The app is designed for Windows environments and uses native Windows networking utilities where available.
- Device notes are stored in a local JSON mapping file and are associated by MAC address, which helps keep notes tied to the device rather than only the IP.
- On rescans, newly discovered devices are highlighted in green to make changes easier to spot.
- The Clear action resets the query and column sort order.

## Requirements

Python 3.10+ on Windows.

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Running

```powershell
python .\mDNS-NetworkScanner-GUI.py
```

## Version

Current version: 1.0.0

## License

This project is distributed under a custom SOSTRAX Shared Source License. Commercial use requires a separate written license agreement.

## Attribution

Designed by Michael Dietz
SOSTRAX
mike@sostrax.com

