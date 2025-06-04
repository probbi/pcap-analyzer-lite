## pcap-analyzer-lite.py – Egyszerű hálózati forgalom elemző

### Leírás

Ez a Python script egy .pcap (Packet CAPture = PCAP) fájlban található hálózati forgalmat elemez, és összesíti a legfontosabb információkat:

 - forrás IP-címek és azok gyakorisága
 - IP protokollok (TCP, UDP, ICMP, stb.) megjelenési aránya
 - leggyakoribb TCP és UDP célportok
 - valamint az egyes forrás IP-címek geolokációs helye (város, ország)

### A geolokációhoz használt GeoLite adatbázis forrása:

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

### A .pcap mintafájl forrása:

https://www.malware-traffic-analysis.net/

---

> [!NOTE]
> A szerző most bontogatja szárnyait és barátkozik a szkriptírással és a Phythonnal.
