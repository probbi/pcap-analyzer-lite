## pcap-analyzer-lite.py – Egyszerű hálózati forgalom elemző

### Leírás

Ez a Python script egy .pcap (Packet CAPture = PCAP) fájlban található hálózati forgalmat elemez, és összesíti a legfontosabb információkat:

 - forrás IP-címek és azok gyakorisága

 - IP protokollok (TCP, UDP, ICMP, stb.) megjelenési aránya

 - leggyakoribb TCP és UDP célportok

 - valamint az egyes forrás IP-címek geolokációs helye (város, ország)

<<<<<<< HEAD
### A geolokációhoz a MaxMind GeoLite2 adatbázist használja

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

- .pcap mintafájl
=======
### A geolokációhoz használt GeoLite adatbázis forrása:

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

### A .pcap mintafájl forrása:
>>>>>>> 57bb4ac (README.hu.md added, README.md removed)

https://www.malware-traffic-analysis.net/
