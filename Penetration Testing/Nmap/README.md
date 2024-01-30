# Content
- [Host Discovery](#host-discovery)
- [Host and Port Scanning](#host-and-port-scanning)
- [Service Enumeration](#service-enumeration)
- [Nmap Scripting Engine](#nmap-scripting-engine)
- [Performance](#performance)
- [Firewall and IDS/IPS Evasion](#firewall-and-idsips-evasion)


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
- `-sV` determine service/version
- `-O` Enable OS detection
- `-A` Enable OS detection, version detection, script scanning, and traceroute
- `--stats-every=n` 5s,5m
- To view the scan status, we can press the [Space Bar]
```bash
sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping
```
- it woth using `nc` to connect open ports if NMAP does not show the version
```
nc -nv 10.129.2.28 25

Connection to 10.129.2.28 port 25 [tcp/*] succeeded!
220 inlane ESMTP Postfix (Ubuntu)
```


## Nmap Scripting Engine

| Category   | Description                                                         |
|------------|---------------------------------------------------------------------|
| auth       | Determination of authentication credentials.                       |
| broadcast  | Host discovery through broadcasting; discovered hosts can be added to remaining scans. |
| brute      | Scripts attempting to log in to services by brute-forcing with credentials. |
| default    | Default scripts executed using the -sC option.                     |
| discovery  | Evaluation of accessible services.                                  |
| dos        | Scripts checking services for denial of service vulnerabilities (used with caution). |
| exploit    | Scripts attempting to exploit known vulnerabilities for the scanned port. |
| external   | Scripts using external services for further processing.             |
| fuzzer     | Scripts for identifying vulnerabilities and unexpected packet handling. |
| intrusive  | Intrusive scripts that could negatively affect the target system.   |
| malware    | Checks for malware infecting the target system.                     |
| safe       | Defensive scripts that do not perform intrusive and destructive access. |
| version    | Extension for service detection.                                    |
| vuln       | Identification of specific vulnerabilities.                        |


1. **Default Scripts**

```
sudo nmap <target> -sC
```

2. **Specific Scripts Category**
```
sudo nmap <target> --script <category>
```

3. **Defined Scripts**
```
sudo nmap <target> --script <script-name>,<script-name>,...
```
## Performance
- `-T <0-5>` speed
- `--min-parallelism <number>` frequency
- `--max-rtt-timeout <time>` and `--initial-rtt-timeout` timeouts
- `--min-rate <number>` simultaneously 
- `--max-retries <number>` number of retries

## Firewall and IDS/IPS Evasion

### Different Source IP
- `-S` can be used to use different source IP
```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O 
```
```bash
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```
if the seconed one gives better result that the first we can use decoys 

### Decoys
- `-D` generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent
- that the decoys must be alive. Otherwise, the service on the target may be unreachable

```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```
