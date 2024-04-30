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



![Screenshot_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/eb4df0e1-72d2-4d25-abcc-f4a309f8be0c)

![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/c54f7dd2-68b3-4f6d-bba9-952b26214a91)



### connect to the victim host

```
C:\Users\Attacker\Desktop\> mstsc.exe # victor:pass@123 to connect to 172.16.6.155.
```

![Screenshot_1](https://github.com/kiro6/penetration-testing-notes/assets/57776872/06839866-3fb1-4bb2-bc8b-c0b534c28f7a)
