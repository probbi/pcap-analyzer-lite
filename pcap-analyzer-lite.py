# file: pcap-analyzer-lite.py
# scapy.all.rdpcap a Scapy egy hálózati csomagkezelő könyvtár. Az rdpcap() függvény segítségével beolvasható egy .pcap fájl, és visszaadja a benne lévő összes csomagot.
#collections.Counter: egy speciális szótár, amely számlálja, hogy hányszor fordul elő egy adott elem.
from scapy.all import rdpcap, TCP, UDP, IP
from collections import Counter
import geoip2.database

# Beállítás: GeoIP adatbázis elérési útja

import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB_PATH = os.path.join(SCRIPT_DIR, "data", "GeoLite2-City.mmdb")
PCAP_FILE_PATH = os.path.join(SCRIPT_DIR, "data", "sample-traffic-analysis-exercise.pcap")

# Protokoll számok és rövidített nevek leképezése
proto_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    
    # ide jöhetnek még protokollok, pl. 2: "IGMP", 89: "OSPF" stb.
}


app_proto_names = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    123: "NTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    22: "SSH",
    21: "FTP",
    20: "FTP (data)",
    23: "Telnet",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-alt",
    # ... lehet bővíteni még igény szerint
}
DETAILED_APP_PROTO = True  # vagy False, ha nem kell a részletes lista
# Beolvassa a megadott .pcap fájlt, és eltárolja a benne lévő összes hálózati csomagot a packets változóban. Ez egy listaszerű objektum lesz, amiben minden elem egy hálózati csomag.
packets = rdpcap(PCAP_FILE_PATH)
# Számlálók inicializálása
# ip_counter: ebben a szótárban számolja meg, hogy melyik forrás IP-cím hányszor fordul elő.

# proto_counter: itt számolja, hogy melyik IP-szintű protokoll (pl. TCP, UDP, ICMP) hányszor jelenik meg.
ip_counter = Counter()
proto_counter = Counter()
port_counter = Counter()

# GeoIP olvasó inicializálása
geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)

ip_locations = {}

# Csomagok feldolgozása
# pkt.haslayer("IP"): csak azokat a csomagokat vizsgálja, amelyek IP réteget tartalmaznak.
# pkt["IP"].src: lekéri a forrás IP-címet.
# pkt["IP"].proto: lekéri az IP protokoll számát (például 6 = TCP, 17 = UDP, 1 = ICMP).
# Ezeket a számlálókat frissíti minden IP csomagra.


for pkt in packets:
    if IP in pkt:
       ip = pkt[IP].src
       ip_counter[ip] += 1
       proto = pkt[IP].proto
       proto_counter[proto] += 1
       
       # Portok vizsgálata
       if TCP in pkt:
            port_counter[pkt[TCP].dport] += 1
       elif UDP in pkt:
            port_counter[pkt[UDP].dport] += 1
       
       # Geolokáció csak egyszer per IP 
       if ip not in ip_locations:
            try:
                response = geo_reader.city(ip)
                city = response.city.name or "Ismeretlen város"
                country = response.country.name or "Ismeretlen ország"
                ip_locations[ip] = f"{city}, {country}"
            except:
                ip_locations[ip] = "Nem található"

geo_reader.close()
            
# Top forrás IP-k és geolokációk
print("\n Top forrás IP-k és helyük:")
for ip, count in ip_counter.most_common(5):
    location = ip_locations.get(ip, "N/A")
    print(f"{ip} ({location}): {count} csomag")

# Protokoll eloszlás kiírása
print("\n Protokoll eloszlás:")
for proto_num, count in proto_counter.items():
    proto_name = proto_names.get(proto_num, f"UNKNOWN({proto_num})")
    print(f"{proto_name}: {count} csomag")

print("\n Leggyakoribb TCP/UDP célportok és alkalmazásréteg protokollok:")
for port, count in port_counter.most_common(10):
    proto_name = app_proto_names.get(port, "Ismeretlen")
    print(f"Port {port} ({proto_name}): {count} csomag")
