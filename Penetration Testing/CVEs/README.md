
## Microsoft Exchange Group Membership

- The group Exchange Windows Permissions is not listed as a protected group, but members are granted the ability to write a DACL to the domain object.
- This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group.
- dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.
- check [this repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges 


## PrivExchange
- The PrivExchange attack results from a flaw in the Exchange Server PushSubscription feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.
- The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update)
- This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain.
- This attack will take you directly to Domain Admin with any authenticated domain user account.
- check [this repo](https://github.com/dirkjanm/PrivExchange)
