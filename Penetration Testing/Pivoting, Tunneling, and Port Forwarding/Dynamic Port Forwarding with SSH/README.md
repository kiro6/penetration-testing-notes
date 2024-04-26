
![Screenshot_1](https://github.com/kiro6/penetration-testing-notes/assets/57776872/b0085376-e147-40b5-bfb6-690e5b466bf5)


enable dynamic port forwarding 
```shell
ssh -D 9050 ubuntu@10.129.202.64
```
route any tool's packets over the port 9050. 
```shell
tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```
using proxychains
```shell
proxychains nmap -v -sn 172.16.5.1-200

# we can only perform a full TCP connect scan over proxychains
proxychains nmap -v -Pn -sT 172.16.5.19

# Using Metasploit with Proxychains
proxychains msfconsole

# Using xfreerdp with Proxychains
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
