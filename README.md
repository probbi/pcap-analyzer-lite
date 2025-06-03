## pcap-analyzer-lite.py – Egyszerű hálózati forgalom elemző

### Leírás

Ez a Python script egy .pcap fájlban található hálózati forgalmat elemez, és összesíti a legfontosabb információkat:

 - forrás IP-címek és azok gyakorisága

 - IP protokollok (TCP, UDP, ICMP, stb.) megjelenési aránya

 - leggyakoribb TCP és UDP célportok

 - valamint az egyes forrás IP-címek geolokációs helye (város, ország)

### A geolokációhoz a MaxMind GeoLite2 adatbázist használja

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

- .pcap mintafájl

https://www.malware-traffic-analysis.net/
