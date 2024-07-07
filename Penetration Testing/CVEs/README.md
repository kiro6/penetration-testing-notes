
## Microsoft Exchange Group Membership

- The group Exchange Windows Permissions is not listed as a protected group, but members are granted the ability to write a DACL to the domain object.
- This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group.
- dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.
- check [this repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges 


## PrivExchange
- The PrivExchange attack results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.
- The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update)
- This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain.
- This attack will take you directly to Domain Admin with any authenticated domain user account.
- check [this repo](https://github.com/dirkjanm/PrivExchange)

## Printer Bug
- The Printer Bug is a flaw in the MS-RPRN protocol (Print System Remote Protocol).
- This protocol defines the communication of print job processing and print system management between a client and a print server.
- To leverage this flaw, any domain user can connect to the spool's named pipe with the RpcOpenPrinter method and use the RpcRemoteFindFirstPrinterChangeNotificationEx method, and force the server to authenticate to any host provided by the client over SMB.
- The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.
- The attack can also be used to relay LDAP authentication and grant Resource-Based Constrained Delegation (RBCD) privileges for the victim to a computer account under our control, thus giving the attacker privileges to authenticate as any user on the victim's computer. This attack can be leveraged to compromise a Domain Controller in a partner domain/forest, provided you have administrative access to a Domain Controller in the first forest/domain already, and the trust allows TGT delegation, which is not by default anymore.
- using this [tool](http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment) We can use `Get-SpoolStatus` module or this [tool](https://github.com/NotMedic/NetNTLMtoSilverTicket)
```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True 
```

## MS14-068
- This was a flaw in the Kerberos protocol, which could be leveraged along with standard domain user credentials to elevate privileges to Domain Admin.
- A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.
- The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group.
- use this [tool](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek)

## MS14-025 Vulnerability in GPP could allow elevation of privilege
- When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:
  - Map drives (drives.xml)
  - Create local users
  - Create printer config files (printers.xml)
  - Creating and updating services (services.xml)
  - Creating scheduled tasks (scheduledtasks.xml)
  - Changing local admin passwords.
- These files can contain an array of configuration data and defined passwords. The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft published the AES private key on MSDN, which can be used to decrypt the password.
- Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share. 
- This was patched in 2014 to prevent administrators from setting passwords using GPP. The patch does not remove `existing` Groups.xml files with passwords from SYSVOL.
- If you delete the GPP policy `instead of` unlinking it from the OU, the cached copy on the local computer remains.

![Screenshot 2024-07-08 at 01-59-36 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/8bd50f57-cf25-4deb-b37e-1237b2ca19fd)


```shell
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```


- tools like netexec or carackmapexec or [Get-GPPAutologon.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1) can be used 
```shell
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```
