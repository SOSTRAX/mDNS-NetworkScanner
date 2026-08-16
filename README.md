\# Network Scanner



A lightweight Windows network scanner being developed as a

custom alternative to tools such as Advanced IP Scanner,

Angry IP Scanner, and SoftPerfect Network Scanner.



\## Current Status



\*\*Version 0.1.0 — Core Scanner Prototype\*\*



The current prototype can:



\- Detect IPv4 networks associated with Windows network adapters

\- Display the adapter name and local IP address

\- Scan an entire IPv4 subnet

\- Scan a start/end IP range

\- Scan a single IP address

\- Discover responding devices using ICMP ping

\- Discover MAC addresses using the Windows ARP table

\- Perform hostname discovery

\- Display scan progress

\- Save and reuse the previous scan range

\- Show the results in a graphical window with a Note column

\- Remember each device note between scans (device\_notes.json)

\- Export functionality is planned



\## Running



```text

python mDNS-NetworkScanner.py            # graphical interface

python mDNS-NetworkScanner.py --console  # original text menu

```



In the graphical interface, double-click a row's Note column

(or select the row and press Enter) to type a note. Notes are

keyed by MAC address, so they follow a device when its IP

address changes.



\## Scan Range Formats



The scanner currently accepts:



```text

192.168.1.0/24

10.40.61.65-10.40.61.67

10.40.61.66

