# Content
## ACL Enumeration with Powerview
- [control-access-rights list](https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights)
- [ace-strings right list](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)
```powershell
# get all intersting acl but can take alot of time
Find-InterestingDomainAcl

# specify one object
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Reverse Search & Mapping to a GUID Value
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

# Creating a List of Domain Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# read from list a specfic user
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

# Investigating the Help Desk Level 1 Group with Get-DomainGroup
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

```

in here the `S-1-5-21-3842939050-3880317879-2865463114-1181` user have `User-Force-Change-Password` right on `S-1-5-21-3842939050-3880317879-2865463114-1176` user
![Screenshot_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/891252fe-052c-4e21-9034-2bbfeaa3eff6)


## ACL Enumeration with BloodHound
- [SharpHound .NET](https://github.com/BloodHoundAD/SharpHound)
- [SharpHound powershell](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)
- [BloodHound]([https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound/releases))
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT

bloodhound 
```
