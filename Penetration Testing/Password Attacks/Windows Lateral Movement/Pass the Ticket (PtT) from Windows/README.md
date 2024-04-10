
- On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. 
- Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

## Harvesting Kerberos Tickets from Windows

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
./mimikatz.exe privilege::debug "sekurlsa::tickets /export"
```

### Rubeus - Export Tickets

```powershell
./Rubeus.exe dump /nowrap
```
