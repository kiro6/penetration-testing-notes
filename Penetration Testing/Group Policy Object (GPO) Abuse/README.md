
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


# Attacks

using [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) we can do alot of attacks 
