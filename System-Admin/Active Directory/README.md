## How Start Pssession between mangment host and DC

- on DC

```powershell
Enable-PSRemoting
## it is enabled by default on windows server core
```

- mangment host
```powershell
Start-Service -Name WinRM

# check if the DC ip in the trustedhosts 
ls  wsman:localhost\client\trustedhosts

Set-item wsman:localhost\client\trustedhosts -value 192.168.56.102 # DC IP

New-PSSession -ComputerName  192.168.56.102 -Credential $(Get-Credential)

Get-PSSession

Enter-PSSession 2 # pssession id
```
