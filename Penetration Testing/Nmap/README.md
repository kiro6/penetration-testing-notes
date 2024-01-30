
## Host Discovery

check [host-discovery-strategies by nmap](https://nmap.org/book/host-discovery-strategies.html)

- `-sn`disable port scanning - ping scan bu default 
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
- `il` get hosts/networks from list 
```
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
- `-PE/PP/PM` ICMP  (echo, timestamp, and netmask request discovery probes)
- `--disable-arp-ping` when you are in local network or vpn will be useful
- `--packet-trace`
- `--reason` reson for result
