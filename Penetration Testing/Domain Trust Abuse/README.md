
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

