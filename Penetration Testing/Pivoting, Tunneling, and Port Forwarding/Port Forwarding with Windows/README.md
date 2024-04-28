
## Netsh

### Using Netsh.exe to Port Forward
```cmd
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

### Verifying Port Forward
```cmd
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

### Connecting to the Internal Host through the Port Forward
```

```
