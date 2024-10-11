
# Enumerating GPO Names 

## using powerview
```powershell
# with PowerView
Get-DomainGPO |select displayname

# with a Built-In Cmdlet
Get-GPO -All | Select DisplayName
```

Enumerating Domain User GPO Rights
```powershell
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```
![Screenshot 2024-07-05 at 02-49-26 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/f9425efd-d0c9-41a4-ae60-da82415af3a3)

Converting GPO GUID to Name
```powershell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```
![Screenshot 2024-07-05 at 02-53-59 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/365e8759-c24b-450c-b6b6-f032de6fd209)



## using bloodhound
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT

bloodhound 
```



here we see that `Domain Users` have control over over `Disconnect Idle RDP` GPO 
![Screenshot 2024-07-05 at 02-50-31 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/599c7d4b-9101-48fd-882a-2c16b0ed6958)

here we can see the affected `OU` and members
![Screenshot 2024-07-05 at 02-50-34 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/4a5f7368-cda9-42dc-a10c-8f32a273acde)


# GPO Enforcement Logic

GPO enforcement logic, very briefly, works like this ([source](https://wald0.com/?p=179)) :

- GpLinks can be enforced, or not.
- OUs can block inheritance, or not.
- If a GpLink is enforced, the associated GPO will apply to the linked OU and all child objects, **regardless** of whether any OU in that tree blocks inheritance.
- If a GpLink is not enforced, the associated GPO will apply to the linked OU and all child  objects, unless any OU within that tree blocks inheritance.



### Things can impact the enforcement logic
- WMI filtering allows administrators to further limit which computers and users a GPO will apply to, based on whether a certain WMI query returns True or False. For example, when a computer is processing group policy, it may run a WMI query that checks if the operating system is Windows 7, and only apply the group policy if that query returns true. See Darren Mar-Elia’s excellent blog post for further details.

- Security filtering allows administrators to further limit which principals a GPO will apply to. Administrators can limit the GPO to apply to specific computers, users, or the members of a specific security group. By default, every GPO applies to the “Authenticated Users” principal, which includes any principal that successfully authenticates to the domain. For more details, see this post on the TechGenix site.

- Group Policy link order dictates which Group Policy “wins” in the event of conflicting, non-merging policies.


### Example

![Screenshot_3](https://github.com/user-attachments/assets/bd875749-a724-4737-9b37-a9321d2ee3ea)

Custom Password Policy is linked to the domain object, which again contains the entire OU tree under it. Now, because the GPLink is enforced, this policy will apply to all child objects in the OU tree, regardless of whether any of those OUs block inheritance. This means that the `Custom Password Policy` GPO will apply to both `Alice Admin` and `Bob User`, despite the `Accounting` OU blocking inheritance.

### BloudHound

#### GPO to OU 
- doted means not enforced
- solid means inforced
#### OU to user or computer
- doted means block inheritance
- solid means inheritance enabled


# Attacks

using [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) we can do alot of attacks 
