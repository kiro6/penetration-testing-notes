
## Kerberoasting
Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket


```powershell
# Get-ADUser filtering for accounts with the ServicePrincipalName property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName



DistinguishedName : CN=User1,CN=Users,DC=example,DC=com
Enabled           : True
Name              : User1
SamAccountName    : User1
ServicePrincipalName : HTTP/server1.example.com

DistinguishedName : CN=User2,CN=Users,DC=example,DC=com
Enabled           : True
Name              : User2
SamAccountName    : User2
ServicePrincipalName : HTTP/server2.example.com
                     HTTP/server3.example.com
                     MSSQLSvc/sqlserver1.example.com

DistinguishedName : CN=User3,CN=Users,DC=example,DC=com
Enabled           : True
Name              : User3
SamAccountName    : User3
ServicePrincipalName : HTTP/server4.example.com
                     MSSQLSvc/sqlserver2.example.com
                     LDAP/server5.example.com
                     CIFS/server6.example.com

```
