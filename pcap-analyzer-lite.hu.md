# Egyszerű hálózati forgalom elemző
## pcap-analyzer-lite.py

### Leírás

Ez a Python script egy .pcap fájlban található hálózati forgalmat elemez, és összesíti a legfontosabb információkat:
 - forrás IP-címek és azok gyakorisága;
 - IP protokollok (TCP, UDP, ICMP, stb.) megjelenési aránya;
 - leggyakoribb TCP és UDP célportok;
 - valamint az egyes forrás IP-címek geolokációs helye (város, ország).

A geolokációhoz a MaxMind GeoLite2 adatbázist használja.

### A szkript használata:

 - töltsd le a GeoLite2-City.mmdb adatbázist a MaxMind oldaláról és tedd a data/ mappába;
 - helyezz el egy .pcap fájlt a data/ mappában (pl. sample-traffic-analysis-exercise.pcap);
 - futtasd a scriptet Python 3 környezetben: `python3 pcap-analyzer-lite.py`;
 - nézd meg az eredményeket a konzolon.
 
### A futtatás utáni eredmények:

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

### Követelmények:

 - Python 3.x
 - Scapy (pip install scapy)
 - geoip2 (pip install geoip2)
 - GeoLite2 City adatbázis (MaxMind)

### Mit tanulhatsz ezzel a projekttel?

 - alapvető hálózati protokollok kezelése Pythonban (IP, TCP, UDP, ICMP);
 - .pcap fájlok feldolgozása Scapy-vel;
 - egyszerű statisztikák készítése Python Counter osztállyal;
 - IP címek geolokációja MaxMind adatbázissal;
 - Python scripting gyakorlása, hibakezelés és kimenet formázás.

### Jövőbeli fejlesztési lehetőségek

 - Forrásportok és egyéb IP réteg attribútumok elemzése.
 - Protokollszűrés vagy időalapú elemzés.
 - Részletesebb alkalmazásréteg elemzés pl. HTTP, DNS.
 - Interaktív vagy webes megjelenítés.
 

### Használt eszközök / könyvtárak

| Eszköz / Könyvtár     | Funkció                              |
| --------------------- | ------------------------------------ |
| `Ubuntu Linux`        | Operációs rendszer                   |
| `tshark`              | Forgalom rögzítése `.pcap` fájlba    |
| `Scapy`               | PCAP beolvasása és elemzése          |
| `geoip2` + `GeoLite2` | IP geolokáció (város, ország)        |
| `venv`                | Python környezet izolálása           |
| `fish shell`          | Alternatív shell, aktiválás módosult |


