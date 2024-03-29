# Content 
- [CMD vs PowerShell](#cmd-vs-powershell)
- [CMD](#cmd)
  -  [Basic Usage](#basic-usage)
  -  [Working with Files and Directories ](#working-with-files-and-directories )
  -  [System Information](#system-information)
  -  [Env Variables](#env-variables)
  -  [Managing Services](#managing-services)
  -  [Working with the Windows Event Log](#working-with-the-windows-event-log)
  -  [Networking Management](#networking-management)
- [PowerShell](#powershell)
  - [Basic Usage](#basic-usage-1)
  - [Working with Files and Directories ](#working-with-files-and-directories-1)
  - [Execution Policy](#execution-policy)
  - [Working With Modules](#working-with-modules)
  - [User and Group Management](#user-and-group-management)
  - [Finding & Filtering Content](#finding--filtering-content)
  - [Working with Services](#working-with-services)
  - [Working with the Registry](#working-with-the-registry)
  - [Working with the Windows Event Log](#working-with-the-windows-event-log-1)
  - [Networking Management](#networking-management-1)

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
rem (for comments)
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

## Working with the Windows Event Log
```CMD
wevtutil

rem Enumerating Log Sources
wevtutil el

rem Gathering Log Information
wevtutil gl "Windows PowerShell"

rem specific status information about the log or log file
wevtutil gli "Windows PowerShell"

rem Querying Events
wevtutil qe Security /c:5 /rd:true /f:text

rem Exporting Events
wevtutil epl System C:\system_export.evtx
```

## Networking Management
```
ipconfig

arp

nslookup 

netstat 
```

# PowerShell 

| Extension | Description                                                          |
|-----------|----------------------------------------------------------------------|
| ps1       | The *.ps1 file extension represents executable PowerShell scripts.  |
| psm1      | The *.psm1 file extension represents a PowerShell module file. It defines what the module is and what is contained within it. |
| psd1      | The *.psd1 is a PowerShell data file detailing the contents of a PowerShell module in a table of key/value pairs. |


## Basic Usage 
```powershell

Get-Help
Update-Help
Get-Location
Get-History
Get-Alias                     ## (print aliases)
Get-Command

Get-Command -verb get         ## list commands with verp get

Get-Command -noun windows*    ## list commands with name windows
```

```powershell
# variable declaration
$name = "John"
$age = 25
$isStudent = $true

# print
Write-Output

# read
Read-Host


# for loop
for ($i = 1 ; $i -le 5 ; $i++){
Write-Output "current value is : $i " 
}

# if condition
$number = 10

if ($number -gt 5) {
    Write-Output "The number is greater than 5."
} elseif ($number -eq 5) {
    Write-Output "The number is equal to 5."
} else {
    Write-Output "The number is less than 5."
}

```


## Working with Files and Directories 
```powershell
# Retrieve an object (could be a file, folder, registry object, etc.)
Get-Item

# Lists out the content of a folder or registry hive.
Get-ChildItem  # Alias: ls / dir / gci

# Create new objects. (Can be files, folders, symlinks, registry entries, and more)
New-Item  # Alias: md / mkdir / ni

# Modify the property values of an object.
Set-Item  # Alias: si

# Make a duplicate of the item.
Copy-Item  # Alias: copy / cp / ci

# Changes the object name.
Rename-Item  # Alias: ren / rni

# Deletes the object.
Remove-Item  # Alias: rm / del / rmdir

# Displays the content within a file or object.
Get-Content  # Alias: cat / type

# Append content to a file.
Add-Content  # Alias: ac

# Overwrite any content in a file with new data.
Set-Content  # Alias: sc

# Clear the content of the files without deleting the file itself.
Clear-Content  # Alias: clc

# Compare two or more objects against each other. This includes the object itself and the content within.
Compare-Object  # Alias: diff / compare

# List directory contents
Get-ChildItem

# Read PowerShell history (can reveal secret info)
Get-Content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Change directory
Set-Location

# Read file
Get-Content
get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt  # read powershell history (can reveal secret info)


```

## Execution Policy
```powershell

Get-ExecutionPolicy                             ## know the Execution Policy

Get-ExecutionPolicy -list                       ## see every scope Execution Policy


Set-ExecutionPolicy Default                     ## set Execution Policy to default options
Set-ExecutionPolicy undefined                   ## set Execution Policy to undefined options

Set-ExecutionPolicy Bypass -Scope Process       ## set Execution Policy bypass for one session (this is the safest option)
Set-ExecutionPolicy Bypass -Scope CurrentUser   ## set Execution Policy bypass this user 
Set-ExecutionPolicy Bypass -Scope LocalMachine  ## set Execution Policy bypass this machine  
```

## working with modules
[powershell gallery](https://www.powershellgallery.com/)
#### install moduels
```powershell

Get-Command -Module PowerShellGet                  ## cmdlets built to manage package installation from the PowerShell Gallery 
Find-Module -Name <module name>                    ## to search in powershell gallery

Find-Module -Name <module name> | Install-Module   ## will install module    
```


#### list modules 
```powershell
Get-Module                       ## list loaded modules
Get-Module -ListAvailable        ## all available modules to load

```

#### importing modules
```powershell
Set-ExecutionPolicy Bypass -Scope Process       ## allow to load module for one session (this is the safest option)

Import-Module .\ModuleName.ps1                  ## import module
```

#### using imported modules
```
Get-Command -Module imported module             ## Calling Cmdlets and Functions From Within a Module
```

## User and Group Management
####
```powershell
# List users in the local machine
Get-LocalUser

# List groups in the local machine
Get-LocalGroup

# List members of a group
Get-LocalGroupMember

# Create a new user
New-LocalUser

# Create a new group
New-LocalGroup

# Edit user properties
Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"

# Edit group properties
Set-LocalGroup

# Add a user to a group
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"

# Remove a user from the local machine
Remove-LocalUser

# Remove a group from the local machine
Remove-LocalGroup

# Remove a user from a group
Remove-LocalGroupMember

# Rename a group
Rename-LocalGroup

# Rename a user
Rename-LocalUser

# Disable a user account
Disable-LocalUser

# Enable a user account
Enable-LocalUser
 

```

## Finding & Filtering Content
```powershell


Select-Object                              ## select and manipulate object properties
Get-Member                                 ## retrieving the members (properties and methods) of objects. 
Sort-Object -Property Name                 ## sort object props by prop name 
Group-Object -property Enabled             ## group object props by prop Enabled

where prop -Like '*Defender*'              ## filter based on prop pattern



## fining files or dir
Get-ChildItem -Path D:\ -File -Recurse | where {($_.Name -like "*.txt")}
Get-ChildItem -Path D:\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}

## dealing with user object
Get-LocalUser administrator | get-member

Get-LocalUser administrator | Get-Member -MemberType Properties

Get-LocalUser administrator | Select-Object -Property *

Get-LocalUser administrator | Get-Member -MemberType Methods

## dealing with service object
get-service | Select-Object -Property Name | Sort-Object Name | fl

get-service | where DisplayName -Like '*Defender*'

```
## Working with Services

```powershell
Get-Service                        
New-Service                             
Restart-Service                 
Resume-Service                
Set-Service                     
Start-Service                                
Stop-Service                               
Suspend-Service


## Remotely Query Services
Get-Service -ComputerName ACADEMY-ICL-DC
Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}     

invoke-command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}

```
## Working with the Registry

```powershell

## displaying information about the registry key itself
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property
Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -Property * 

## see each key and object within a hive
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse

## retrieving and displaying the values associated with the properties (entries) within the key
Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg.exe query 'HKEY_LOCAL_MACHINE\SOFTWARE\Android Studio'

## search for passwords keys using reg
REG QUERY HKCU /F "password" /t REG_SZ /S /K

New-Item
Set-Item
New-ItemProperty
Set-ItemProperty

## create new key
New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey

## add values to the key
New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"  
```

## Working with the Windows Event Log
```powershell
## Listing All Logs
Get-WinEvent -ListLog *

## Security Log Details
Get-WinEvent -ListLog Security

## Querying Events
Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message

## Filtering 
Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}
Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message

```

## Networking Management
```powershell
# PowerShell script to perform various network-related tasks

# Retrieve all visible network adapter properties
Get-NetIPInterface

# Retrieves the IP configurations of each adapter (Similar to IPConfig)
Get-NetIPAddress

# Retrieves the neighbor entries from the cache (Similar to arp -a)
Get-NetNeighbor

# Print the current route table (Similar to IPRoute)
Get-NetRoute

# Set basic adapter properties at the Layer-2 level such as VLAN id, description, and MAC-Address
Set-NetAdapter -InterfaceAlias "Ethernet" -Description "New Description" -MacAddress "00:11:22:33:44:55" -VlanID 10

# Modifies the settings of an interface to include DHCP status, MTU, and other metrics
Set-NetIPInterface -InterfaceAlias "Ethernet" -Dhcp Enabled -Mtu 1500 -NlMtu 1400

# Creates and configures an IP address
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.100" -PrefixLength 24

# Modifies the configuration of a network adapter
Set-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.101" -PrefixLength 24

# Disable network adapter interfaces
Disable-NetAdapter -InterfaceAlias "Ethernet"

# Enable network adapters to allow network connections
Enable-NetAdapter -InterfaceAlias "Ethernet"

# Restart a network adapter (useful to push changes made to adapter settings)
Restart-NetAdapter -InterfaceAlias "Ethernet"

# Perform diagnostic checks on a connection (supports ping, tcp, route tracing, etc.)
Test-NetConnection -ComputerName "example.com" -Port 80 -InformationLevel Detailed

```
