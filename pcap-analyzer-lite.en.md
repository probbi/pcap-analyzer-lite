# Simple network traffic analyser
## pcap-analyzer-lite.py
### Description

This Python script analyzes network traffic in a .pcap file and summarizes the most important information:

 - Source IP addresses and their frequency;
 - IP protocols (TCP, UDP, ICMP, etc.) appearance rate;
 - most common TCP and UDP destination ports;
 - and the geolocation (city, country) of each source IP address.

For geolocation, the MaxMind GeoLite2 database is used.

### Using the script:

 - Download the GeoLite2-City.mmdb database from the MaxMind site and put it in the data/ folder;
 - place a .pcap file in the data/ folder (e.g. sample-traffic-analysis-exercise.pcap);
 - run the script in Python 3: python3 pcap-analyzer-lite.py;
 -  view the results on the console.

The results after running (in the script, the commented parts and prints are in Hungarian):

```
📊 Top forrás IP-k és helyük:
172.16.4.205 (Nem található): 13357 csomag
185.243.115.84 (Frankfurt am Main, Germany): 8571 csomag
166.62.111.64 (Ismeretlen város, United States): 5677 csomag
172.16.4.4 (Nem található): 457 csomag
31.13.70.52 (Los Angeles, United States): 218 csomag

📦 Protokoll eloszlás:
UDP: 190 csomag
IGMP: 8 csomag
TCP: 29011 csomag

🔢 Leggyakoribb TCP/UDP célportok és alkalmazásréteg protokollok:
Port 80 (HTTP): 12293 csomag
Port 49249 (Ismeretlen): 8571 csomag
Port 49201 (Ismeretlen): 1522 csomag
Port 49200 (Ismeretlen): 1051 csomag
Port 49198 (Ismeretlen): 940 csomag
Port 49190 (Ismeretlen): 848 csomag
Port 49202 (Ismeretlen): 697 csomag
Port 49199 (Ismeretlen): 616 csomag
Port 443 (HTTPS): 540 csomag
Port 49223 (Ismeretlen): 163 csomag
```
   
### Requirements:

 - Python 3.x
 - Scapy (pip install scapy)
 - Pyapy 3.xapy (pip install geoip2)
 - GeoLite2 City database (MaxMind)

### What I can learn from this project?

 - Basic network protocol management in Python (IP, TCP, UDP, ICMP);
 - processing .pcap files with Scapy;
 - create simple statistics with Python Counter class;
 - IP address geolocation with MaxMind database;
 - Python scripting practice, error handling and output formatting.

### Future development opportunities

 - Analysis of source ports and other IP layer attributes.
 - Protocol filtering or time-based analysis.
 - More detailed application layer analysis e.g. HTTP, DNS.
 
### Interactive or web visualisation.

| Tools / libraries used| Function                               |
| --------------------- | -------------------------------------- |
| `Ubuntu Linux`        | Operating System                       |
| `tshark`              | Capture traffic to .pcap file          |
| `Scapy`               | PCAP scan and analysis                 |
| `geoip2` + `GeoLite2` | IP geolocation (city, country)         |
| `venv`                | Python environment isolation           |
| `fish shell`          | Alternative shell, activation modified |

