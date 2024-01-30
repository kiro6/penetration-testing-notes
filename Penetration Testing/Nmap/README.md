# Content
- [Host Discovery](#host-discovery)
- [Host and Port Scanning](#host-and-port-scanning)
- [Service Enumeration](#service-enumeration)


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
- `-PU` UDP ping scan , `-PT` TCP ping scan
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
| open\|filtered    | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port.  |
| closed\|filtered  | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.  |


- `-n` for Disables DNS resolution.
- `-Pn` disable ping when yor know the port is opned to low traffic
- `-A` enable os detection
- `--top-ports=n`

### port scan types 

1. **`-sS` (TCP SYN Scan):**
   - This is the default scan type. It sends a SYN packet to the target port.
   - If the port is open, the target responds with a SYN-ACK, indicating that the port is open.
   - If the port is closed, the target responds with a RST (reset) packet.

Example:
```bash
   nmap -sS target_ip
```

2. **`-sT` (TCP Connect Scan):**
- It attempts to establish a full TCP connection to the target port.
- If successful, it means the port is open.
```bash
nmap -sT target_ip
```

3. **`-sA` (TCP ACK Scan):**
- It sends an ACK packet to the target port.
- If the port is unfiltered, the target responds with a RST, indicating the port is closed.
- If the port is filtered, there is no response.
```bash
nmap -sA target_ip
```

4. **`-sW` (TCP Window Scan):**
- This scan type looks at the TCP window size in the response.
- The TCP window size is a parameter in the TCP header that specifies the amount of data, in bytes
- The -sW option in Nmap sends a SYN packet to the target port, just like a SYN Scan (-sS). However, instead of focusing on whether the port is open based on a SYN-ACK or RST response, the Window Scan is interested in the TCP window size.
- If the window size is non-zero, Nmap considers the port as open.
- If the window size is zero, Nmap considers the port as closed.
```bash
nmap -sW target_ip
```

5. **`-sM` (TCP Maimon Scan):**
- The Maimon Scan sends a combination of TCP flags—FIN (Finish), URG (Urgent), and PUSH
- If the target port is closed, the normal response would be a RST (reset) packet
- If the port is open , the system does not respond

```bash
nmap -sM target_ip
```

6. **`-sU` (UDP Scan):**
- Nmap sends a empty UDP packet to each specified target port
- If we get an ICMP response with error code 3 (port unreachable), we know that the port is indeed closed.
- If the target port is open, the system may respond with a UDP packet OR not
```bash
nmap -sU target_ip
```

7. **`-sN` (TCP Null Scan):**
- Nmap sends TCP packets with none of the flags set
- If the system does not respond the port is open
- If the target port is closed, the normal response is a TCP RST
```
nmap -sN target_ip
```

8. **`-sX`(TCP Xmas Scan):**
Sets FIN, URG, and PUSH flags in TCP packets. Similar to Null Scan but uses additional flags.


## Service Enumeration
