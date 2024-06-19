# Content
## ACL Enumeration
- [control-access-rights list](https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights)
```powershell
# get all intersting acl but can take alot of time
Find-InterestingDomainAcl

# specify one object
$sid = Convert-NameToSid wley
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Reverse Search & Mapping to a GUID Value
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

# Using the -ResolveGUIDs Flag
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
```
