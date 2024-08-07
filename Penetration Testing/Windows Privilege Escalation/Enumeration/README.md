



### Network 

```powershell

# Interface(s), IP Address(es), DNS Information
ipconfig /all

# ARP Table
arp -a

# Routing Table
route print
```

### System Information
```powershell
# list running processes
tasklist /svc

# Display All Environment Variables 
set

# View Detailed Configuration Information | check Hotfix section
systeminfo

# check Hotfix
wmic qfe
Get-HotFix | ft -AutoSize

# Installed Programs
wmic product get name
Get-WmiObject -Class Win32_Product |  select Name, Version

# display active network connections
netstat -ano

# Listing Named Pipes with Pipelist => https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist
pipelist.exe /accepteula

# Listing Named Pipes with PowerShell
gci \\.\pipe\


# Reviewing LSASS Named Pipe Permissions using accesschk => https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
accesschk.exe /accepteula \Pipe\lsass -v

```

### Enumerating Protections

```powershell
# Check Windows Defender Status
Get-MpComputerStatus

# List AppLocker Rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections


# Test AppLocker Policy
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

```

### User & Group Information
```
# Logged-In Users
query user

# Current User
echo %USERNAME%

# Current User Privileges
whoami /priv

# Current User Group Information
whoami /groups

# Get All Users
net user

# Get All Groups
net localgroup

# Details About a Group
net localgroup administrators

# Get Password Policy & Other Account Information
net accounts

```
