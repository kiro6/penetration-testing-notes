
## Host Discovery
- `-sn` disable port scanning
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
