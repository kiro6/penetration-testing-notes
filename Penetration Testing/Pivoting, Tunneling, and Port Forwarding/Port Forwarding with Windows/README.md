
## Netsh

![Screenshot_5](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ab4f9ed3-70a3-4e50-b625-c0472ef3e1e2)


### Using Netsh.exe to Port Forward
you tell the windows pivot to forward every coming req to port 8080 to `172.16.5.25` internal ip with port `3389`
```cmd
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

### Verifying Port Forward
```cmd
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

### Connecting to the Internal Host through the Port Forward
```
$  xfreerdp  -f /v:10.129.15.150:8080 /u:victor /p:pass@123
```
