# Content
- [Network](#network)
- [System Information](#system-information)
- [Enumerating Protections](#enumerating-protections)
- [User & Group Information](#user--group-information)
- [Creds](#creds)



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
```powershell
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

### creds

```powershell
# Searching for patterns in Files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /SIM /C:"password" C:\Users\*.txt C:\Users\*.ini C:\Users\*.cfg C:\Users\*.config C:\Users\*.xml
Get-ChildItem -Path C:\Users -Include *.txt, *.ini, *.cfg, *.config, *.xml -Recurse | Get-Content | Select-String "password"
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

Get-ChildItem C:\Users -Include *.txt, *.ini, *.cfg, *.config, *.xml -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object { 
    Select-String "password" $_.FullName -ErrorAction SilentlyContinue | 
    ForEach-Object { Write-Host "Match found in: $($_.Path)"; $_ }
}

Get-ChildItem -Path C:\Users -Include *.txt, *.ini, *.cfg, *.config, *.xml -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object {
    try {
        $content = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
        if ($content | Select-String "password") {
            Write-Host "Match found in file: $($_.FullName)"
            $content | Select-String "password"
        }
    } catch { }
}

# srarch for file extenstions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ *.config
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore


# Chrome Dictionary Files
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password


# PowerShell History File
(Get-PSReadLineOption).HistorySavePath
gc (Get-PSReadLineOption).HistorySavePath
## for all users
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}


# PowerShell Credentials
## PowerShell credentials in scripts stored using DPAPI are encrypted and can only be decrypted by the same user on the same computer where they were created.
## Decrypting PowerShell Credentials
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password


# Sticky Notes Passwords
## C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
Import-Module .\PSSQLite.psd1  ; $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite' ; Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
strings plum.sqlite-wal
```

- other intersting files
```powershell
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```
