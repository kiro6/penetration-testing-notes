
## Host Discovery

check [host-discovery-strategies by nmap](https://nmap.org/book/host-discovery-strategies.html)

- `-sn` ping scan - disable port scanning
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
- `il` get hosts/networks from list 
```
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
