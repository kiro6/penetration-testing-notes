## plink.exe
![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/3f3e97ce-565d-4f6a-94cb-c06aefa08b95)

This starts an SSH session between the Windows attack host and the Ubuntu server, and then plink starts listening on port 9050.
```shell
plink -ssh -D 9050 ubuntu@10.129.15.50
```

Proxifier can be used to start a SOCKS tunnel via the SSH session we created. 

![Screenshot 2024-04-28 at 23-12-37 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/1dc0a8e9-5ae5-4a54-9e5d-0e8253f0218b)


we can directly start `mstsc.exe` to start an RDP session with a Windows target that allows RDP connections.
