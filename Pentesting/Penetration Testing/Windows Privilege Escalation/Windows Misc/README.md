
## Add Exclusion on Windows Defender
```powershell
# need to be admin or system auth priv 
powershell -ep bypass
Add-MpPreference -ExclusionPath c:\temp
```

## Disable Windows Defender
```powershell
powershell -ep bypass
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Allow RDP over firewall

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
New-NetFirewallRule -DisplayName 'Remote Desktop' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389        
```

## Net Command

```powershell
# add user to domain
net user <username> <pass> /add /domain

# add user to gorup
net group <Groupname> <username> /add /domain

# Get All Users
net user

# Get All Groups
net localgroup

# Details About a Group
net localgroup administrators
```
