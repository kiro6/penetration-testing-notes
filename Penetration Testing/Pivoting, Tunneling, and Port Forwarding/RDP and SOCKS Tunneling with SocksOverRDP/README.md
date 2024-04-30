if we have a windows machine to attack and we want to make a pivot 


we will need in out attack machine : 
- [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
- [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

### Loading SocksOverRDP.dll using regsvr32.exe
```
C:\Users\Attacker\Desktop\> regsvr32.exe SocksOverRDP-Plugin.dll

```

### start server at the picot target 
```shell
mstsc.exe # victor:pass@123 to connect to 172.16.5.19.

C:\Users\Pivot\Desktop> ./SocksOverRDP-Server.exe
```

### Confirming the SOCKS Listener is Started in Our attack machine
```
netstat -antb | findstr 1080

  TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

### Configuring Proxifier in our attack machine 
it will use Proxifier to pivot all our traffic via 127.0.0.1:1080, which will tunnel it over RDP to 172.16.5.19, which will then route it to 172.16.6.155 using SocksOverRDP-server.exe.

### connect to the victim host

```
mstsc.exe # victor:pass@123 to connect to 172.16.6.155.
```
