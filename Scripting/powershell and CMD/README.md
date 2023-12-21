# Content 
- [CMD vs PowerShell](#cmd-vs-powershell)
- [CMD](#cmd)
  -  [Basic Usage](#basic-usage)
  -  [Working with Files and Directories ](#working-with-files-and-directories )
  -  [System Information](#system-information)
  -  [Env Variables](#env-variables)
  -  [Managing Services](#managing-services)

# CMD vs PowerShell
| Feature              | CMD                                       | PowerShell                                                   |
|----------------------|-------------------------------------------|-------------------------------------------------------------|
| Language             | Batch and basic CMD commands only.         | PowerShell can interpret Batch, CMD, PS cmdlets, and aliases.|
| Command Utilization  | The output from one command cannot be passed into another directly. | The output from one command can be passed into another directly.|
| Command Output       | Text only                                 | PowerShell outputs in object formatting.                     |
| Parallel Execution   | CMD must finish one command before running another. | PowerShell can multi-thread commands to run in parallel.     |


# CMD 
## Basic Usage 
[quick reference](https://ss64.com/nt/)
```cmd
"rem"                 rem (for comments)
help                rem help
command /?          rem help
doskey /history              
cls                 rem (clear)
|                   rem (pipline)
> and >>            rem output redirection
<                   rem input redirection
A & B               rem (run A then B)
A && B              rem (do B if A successed)
A || B              rem (do B if A fails)
find                rem (like grep in linux)
findstr             rem (like grep in linux)
where               rem (`where PATH  file_want_to_find` or `where file` will search in path env )
sort
fc                  rem (check diff between files)
comp                rem (compare byte to byte)
```

## Working with Files and Directories 
- `cd` or `chdir `  (change dir)
- `dir`             (list dir) (`dir /A:H /A:D` for hidden files/dir)
- `tree`            (tree dir)
- `md` or `mkdir`   (create dir)
- `rd` or `rmdir`   (remove dir) (add `\S` for recusrive)
- `move`            (move file/dir or rename it)
- `xcopy`           (copy file/dir) (can be usefule for hacker it does not copy ACL attributes)
- `robocopy`        (copy file/dir)
- `copy`            (copy file)
- `more`            (read file)
- `type`            (read file)
- `del`             (delete file)
- `erase`           (delete file)      
- `ren`             (rename file)
- `fsutil`          (It allows users to perform tasks related to the file system)

## System Information
![InformationTypesChart_Updated_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/1d8ac151-10e9-48a8-898f-f658c58a23ab)

- `systeminfo`
- `hostname`
- `ver`
- `ipconfig`         (`/all` )
- `arp`              (`/a`)
- `whoami`           (`/priv`,`/group`)

### `net` command
```cmd 
net user         rem  allows us to display a list of all users on a host, information and to create or delete users
net localgroup
net group        rem  manage local or domain groups on a computer. must be run against a domain server such as the DC
net share        rem  display or configure shared resources on a computer. 
net view         rem  display a list of resources, such as computers or shared resources, that are available on the network. This includes domain resources, shares, printers, and more.
net start        rem  start a service and list all services in the system
net stop         rem  stop a service
net pause        rem  pause a service
net continue     rem  continue a service
```

### `WMIC` command

## Env Variables

### environment variables types

| Scope            | Permissions Required to Access                   | Registry Location                                               |
|-------------------|-------------------------------------------------|-----------------------------------------------------------------|
| System (Machine)  | Local Administrator or Domain Administrator      | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` |
| User              | Current Active User, Local Administrator, or Domain Administrator | `HKEY_CURRENT_USER\Environment`                                  |
| Process           | Current Child Process, Parent Process, or Current Active User | None (Stored in Process Memory)                                  |





- `%variable_name%`  (access variable)
- `set`              (Process scope)(set var will be removed when the cmd session end)
- `setx`             (user scope)(set a var will hat persists across sessions even after restarting the computer)
- `setx /M`          (system scope)
- `set/setx var_name=""`  (will delete the env variable)
EX: 
```cmd
C:\Users\alice> set SECRET_VAR=VerySecretInfo
C:\Users\alice> echo %SECRET%
VerySecretInfo

C:\Users\alice> setx SECRET_VAR "VerySecretInfo"

```

## Managing Services
- `sc` (Service Controller)
```cmd
sc query type= service                      rem  Query All Active Services

sc query <service name>                     rem  Querying for service

sc start <service name>                     rem  Starting Services

sc stop <service name>                      rem  Stopping Services

sc config <service name> start= disabled    rem  Modifying Services
```

- `tasklist` (list of currently running processes)
```
tasklist /svc
```

# PowerShell 

## Basic Usage 
- `Get-Help`
- `Update-Help`
- `Get-Location`
- `Get-History`
- `Get-Alias`  (print aliases)
- `Get-Command`
```powershell
Get-Command -verb get         # list commands with verp get

Get-Command -noun windows*    # list commands with name windows
```

## Working with Files and Directories 
- `Get-ChildItem` (list dir)
```powershell
get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt  # read powershell history (can reveal secret info)
```
- `Set-Location`  (change dir)
- `Get-Content`   (read file)
- 
## working with modules

#### list modules 
```powershell
Get-Module                       ## list loaded modules
Get-Module -ListAvailable        ## all available modules to load

```

#### importing modules
```powershell
Set-ExecutionPolicy Bypass -Scope Process       ## allow to load module for one session (this is the safest option)
Set-ExecutionPolicy Bypass -Scope CurrentUser   ## allow to load module for this user 
Set-ExecutionPolicy Bypass -Scope LocalMachine  ## allow to load module for this machine  

Import-Module .\ModuleName.ps1                  ## import module
```

