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
