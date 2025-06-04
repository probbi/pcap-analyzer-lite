## pcap-analyzer-lite.py - Simple network traffic analyzer

### Description

This Python script analyzes network traffic in a .pcap (Packet CAPture = PCAP) file and aggregates the most important information:

 - source IP addresses and their frequency
 - IP protocols (TCP, UDP, ICMP, etc.) appearance rate
 - most common TCP and UDP destination ports and the geolocation (city, country) of each source IP address

### Source of the GeoLite database used for geolocation:

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

### Source of the sample .pcap file

https://www.malware-traffic-analysis.net/
