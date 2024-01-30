
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


## Host and Port Scanning

| State            | Description                                                                                                                     |
|------------------|---------------------------------------------------------------------------------------------------------------------------------|
| open             | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations.  |
| closed           | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not.  |
| filtered         | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.  |
| unfiltered       | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.  |
| open|filtered    | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port.  |
| closed|filtered  | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.  |
