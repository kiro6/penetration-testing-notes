# Content
- [Active Directory Structure](#active-directory-structure)
- [Organizational unit](#organizational-unit)
- [Group Policy Objects](#group-policy-objects)
  - [GPO types](#gpo-types)   
- [Active Directory Objects](#active-directory-objects)
  - [Domain](#domain)
  - [Domain Controllers](#domain-controllers)
  - [Sites](#sites)
  - [Built-in](#built-in)
  - [Foreign Security Principals](#foreign-security-principals)
  - [Users](#users)
  - [Computers](#computers)
  - [Groups](#groups)
  - [Contacts](#contacts)
  - [Printers](#printers)
  - [Shared Folders](#shared-folders)
- [Distinguished Name & Relative Distinguished Name](#distinguished-name--relative-distinguished-name)
- [Flexible Single Master Operations(FSMO) Roles](#flexible-single-master-operationsfsmo-roles)
- [Active Directory Protocols](#active-directory-protocols)
  - [LDAP](#ldap)
  - [Kerberos](#kerberos)
  - [NTHash (NTLM)](#nthash-ntlm)
  - [NTLMv1 (Net-NTLMv1)](#ntlmv1-net-ntlmv1)
  - [NTLMv2 (Net-NTLMv2)](#ntlmv2-net-ntlmv2)
  



## Active Directory Structure

![Screenshot_8](https://github.com/kiro6/penetration-testing-notes/assets/57776872/d2fa839d-504e-419e-ac02-22651486362d)

### Trusts
| Trust Type    | Description                                                                                                                     |
|---------------|---------------------------------------------------------------------------------------------------------------------------------|
| Parent-child  | Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.                        |
| Cross-link    | A trust between child domains to speed up authentication.                                                                       |
| External      | A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust.        |
| Tree-root     | A two-way transitive trust between a forest root domain and a new tree root domain. Created when setting up a new tree root domain within a forest. |
| Forest        | A transitive trust between two forest root domains.                                                                              |


### Directions

| **Type of Trust**  | **Description**                                                                                                                                                                      | **Example**                                                                                   |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| **One-Way**        | Users in a trusted domain can access resources in a trusting domain, not vice-versa.                                                                                                 | Users in Domain A can access resources in Domain B, but users in Domain B cannot access resources in Domain A. |
| **Bidirectional**  | Users from both trusting domains can access resources in the other domain.                                                                                                           | Users in INLANEFREIGHT.LOCAL can access resources in FREIGHTLOGISTICS.LOCAL, and vice-versa.  |


![Screenshot_9](https://github.com/kiro6/penetration-testing-notes/assets/57776872/d7bab82f-f01e-400c-af1b-481541f2f876)

### Transitive

| Trust Type        | Description                                                                                                         | Example                                                                                                             |
|-------------------|---------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Transitive Trust  | Trust is extended to objects that the child domain trusts.                                                          | If Domain A trusts Domain B, and Domain B has a transitive trust with Domain C, then Domain A will trust Domain C.  |
| Non-Transitive Trust | The child domain itself is the only one trusted.                                                                 | Domain A trusts Domain B only, regardless of any trusts Domain B might have with other domains.                    |

![Screenshot 2024-07-08 at 03-10-20 Hack The Box - Academy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/3cfe2cf4-dc3f-476e-95e8-a0854e9831e4)



## Organizational unit
- An Organizational Unit (OU) in Active Directory is a logical container object used to organize and manage users, groups, computers, and other Active Directory objects within a domain. 
- can apply policy using `Group Policy`

![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/59e4ee58-42c3-4aba-8f7f-30347151ee22)



## Group Policy Objects 
Group Policy Objects (GPOs) can be linked to OUs to apply specific configurations, settings, and policies to the objects within those OUs. This allows administrators to apply different policies based on the requirements of different departments or organizational units.

![Screenshot_1](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a0c7ec7a-de08-405b-b48c-43e0ec1b45a3)


![Screenshot_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/6fadfe24-f2e4-4e40-b5e3-d213dfbc96ac)



#### for example : 
- Password Policy: Enforce password complexity requirements, minimum password length, and password expiration policies to enhance security.

- Account Lockout Policy: Configure settings to lock out user accounts after a certain number of incorrect login attempts, helping to prevent unauthorized access.

- Software Installation: Automatically install software applications on users' computers upon startup or user login, ensuring consistent software deployment across the organization.


### GPO types

| Level                           | Description                                                                                                                                                                                                                                                                                                                               |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Local Group Policy              | The policies are defined directly to the host locally outside the domain. Any setting here will be overwritten if a similar setting is defined at a higher level.                                                                                                                                                                       |
| Site Policy                     | Any policies specific to the Enterprise Site that the host resides in. Remember that enterprise environments can span large campuses and even across countries. So it stands to reason that a site might have its own policies to follow that could differentiate it from the rest of the organization. Access Control policies are a great example of this. Say a specific building or site performs secret or restricted research and requires a higher level of authentication for access to resources. You could specify those settings at the site level and ensure they are linked so as not to be overwritten by domain policy. This is also a great way to perform actions like printer and share mapping for users in specific sites. |
| Domain-wide Policy             | Any settings you wish to have applied across the domain as a whole. For example, setting the password policy complexity level, configuring a Desktop background for all users, and setting a Notice of Use and Consent to Monitor banner at the login screen.                                                                                                                                |
| Organizational Unit (OU)       | These settings would affect users and computers who belong to specific OUs. You would want to place any unique settings here that are role-specific. For example, the mapping of a particular share drive that can only be accessed by HR, access to specific resources like printers, or the ability for IT admins to utilize PowerShell and command-prompt.                                                              |
| Any OU Policies nested within other OUs | Settings at this level would reflect special permissions for objects within nested OUs. For example, providing Security Analysts a specific set of Applocker policy settings that differ from the standard IT Applocker settings.                                                                                                                                                                      |


![Screenshot_4](https://github.com/kiro6/penetration-testing-notes/assets/57776872/d2eadbff-043d-49c0-aae5-bba627ae372a)


## Active Directory Objects 


### Domain
- A domain is the structure of an AD network. Domains contain objects such as users and computers, which are organized into container objects: groups and OUs.
- Every domain has its own separate database and sets of policies that can be applied to any and all objects within the domain.

### Domain Controllers
- Domain Controllers are essentially the brains of an AD network.
- They handle authentication requests, verify users on the network, and control who can access the various resources in the domain.
- All access requests are validated via the domain controller and privileged access requests are based on predetermined roles assigned to users.
- It also enforces security policies and stores information about every other object in the domain.

### Sites
- A site in AD is a set of computers across one or more subnets connected using high-speed links. 
- They are used to make replication across domain controllers run efficiently.

### Built-in
- In AD, built-in is a container that holds default groups in an AD domain. They are predefined when an AD domain is created.


### Foreign Security Principals
- A foreign security principal (FSP) is an object created in AD to represent a security principal that belongs to a trusted external forest.
- They are created when an object such as a user, group, or computer from an external (outside of the current) forest is added to a group in the current domain.
- They are created automatically after adding a security principal to a group.
- Every foreign security principal is a placeholder object that holds the SID of the foreign object (an object that belongs to another forest.)
- Windows uses this SID to resolve the object's name via the trust relationship.
- FSPs are created in a specific container named ForeignSecurityPrincipals with a distinguished name like `CN=ForeignSecurityPrincipals,DC=domain1,DC=com` or for a user in it `CN=User1,ForeignSecurityPrincipals,DC=domain1,DC=com`.

### Users
- Users are considered leaf objects, which means that they cannot contain any other objects within them
- A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID).
- User objects have many possible attributes, such as their display name, last login time, date of last password change, email address, account description, manager, address, and more.
- [all active directory user object attributes](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/)

### Groups
**there are 2 types of groups** 
1) **security Group:**
used to manage access permissions to resources such as files, folders, printers, and other objects within the network. Security groups allow you to grant or deny access to these resources based on the membership of users or other groups.

2) **Distribution Groups:**
These are used primarily for email distribution purposes. Distribution groups allow you to send emails to multiple recipients by simply addressing the email to the group rather than individual email addresses.


**there 3 types of scope:** 

1) **Domain Local Groups**
2) **Global Groups**
3) **Universal Groups**


| Group Scope        | Can Contain                                             | Cannot Contain                                     |
|--------------------|---------------------------------------------------------|-----------------------------------------------------|
| Global Groups      | Users from the same domain, global groups from the same domain | Users from other domains or forests, local groups |
| Domain Local Groups| Users, global groups from the same domain, universal groups from any domain within the forest, users or groups from any trusted forest | Users or groups from other forests |
| Universal Groups   | Users from any domain within the forest, global groups from any domain within the forest, other universal groups | Users or groups from trusted external forests |


In a small environment, there's really no difference in practicebut in an environment with multiple domains and/or forests, a common approach to managing permissions involves using domain local groups to attach permissions to resources. Then, access is granted via universal groups, which can span across domains within the forest. Finally, global groups containing users are added to the universal groups.

So, the flow would typically be:
- Permissions are assigned to local groups for specific resources within a domain.
- Users are added to global groups within their respective domains based on their roles or permissions requirements.
- These global groups are then added to universal groups, which serve as a way to aggregate permissions across multiple domains within the forest.
- Finally, the universal groups are granted access to the resources by being added to the appropriate local groups that have the necessary permissions.


### Computers
- A computer object is any computer joined to the AD network (workstation or server). 
- Computers are leaf objects because they do not contain other objects. However, they are considered `security principals` and have a `SID and a GUID` .
- Like users, they are prime targets for attackers since full administrative access to a computer (as the all-powerful NT AUTHORITY\SYSTEM account) grants similar rights to a standard domain user and can be used to perform the majority of the enumeration tasks that a user account can (save for a few exceptions across domain trusts.)

### Contacts 
- In Active Directory, "Contacts" refer to objects used to represent external entities, such as people or resources, who are not part of the Active Directory domain.
- They are leaf objects and are NOT security principals (securable objects), so they don't have a SID, only a GUID. 
- Contacts are typically created for entities outside of the organization, such as partners, clients, vendors, or individuals in other domains.
- Administrators can define permissions for Contacts, specifying who can view, modify, or delete them. This allows for controlled access to contact information within the organization.


![Screenshot_6](https://github.com/kiro6/penetration-testing-notes/assets/57776872/7b6c6d9f-6c52-47dc-96ed-60270d6b042e)


### Printers
- A printer object points to a printer accessible within the AD network. Like a contact, a printer is a leaf object and `not a security principal`, so it only has a `GUID`. 
- Printers have attributes such as the printer's name, driver information, port number, etc.

### Shared Folders
- A shared folder object points to a shared folder on the specific computer where the folder resides.
- Shared folders can have stringent access control applied to them and can be either accessible to everyone (even those without a valid AD account), open to only authenticated users (which means anyone with even the lowest privileged user account OR a computer account (NT AUTHORITY\SYSTEM) could access it), or be locked down to only allow certain users/groups access. Anyone not explicitly allowed access will be denied from listing or reading its contents.
- Shared folders are NOT security principals and only have a GUID. 
- A shared folder's attributes can include the name, location on the system, security access rights.

### Organizational Units
[Organizational unit](#organizational-unit)





## Distinguished Name & Relative Distinguished Name
- A Distinguished Name (DN) describes the full path to an object in AD `(such as cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local)`
- A Relative Distinguished Name (RDN) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. In our example `The Common Name (CN), bjones`

![Screenshot_5](https://github.com/kiro6/penetration-testing-notes/assets/57776872/39be0a60-df9f-495b-a8d3-626e3d66edd2)



## Flexible Single Master Operations(FSMO) Roles
Microsoft introduced the concept of FSMO roles, which designate specific domain controllers within the Active Directory environment to perform certain critical operations.

Think of it of a way to seperate servcices instead of runing this on a single machine when a DC server is assigned to any role it will a have the servcices related to that role runing on it 



### Per Forest
**Schema Master:**
- Manages the read/write copy of the Active Directory schema.
- Controls the structure and attributes of objects stored in Active Directory.
- Responsible for making changes to the schema, such as adding or modifying attributes.

**Domain Naming Master:**
- Manages domain names within the forest.
- Ensures the uniqueness of domain names across the entire forest.
- Controls the addition or removal of domains from the forest.

### Per Domain
**Relative Identifier (RID) Master:**
- Allocates unique Relative Identifiers (RIDs) to objects within a domain.
- Ensures that each object in the domain has a unique security identifier (SID).
- Prevents SID conflicts by managing RID pools.

**Primary Domain Controller (PDC) Emulator:**
- Provides backward compatibility for older Windows clients.
- Handles authentication requests, password changes, and time synchronization.
- Acts as the primary source for Group Policy updates within the domain.

**Infrastructure Master:**
- Updates references to objects in other domains within the same forest.
- This role translates GUIDs, SIDs, and DNs between domains
- Ensures that cross-domain object references are properly maintained.
- Only relevant in domains where not all domain controllers are also Global Catalog servers.
- If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.


## Active Directory Protocols


### LDAP
- LDAP is how systems in the network environment can "speak" to AD
- The relationship between AD and LDAP can be compared to Apache and HTTP, Active Directory is a directory server that uses the LDAP protocol.

![Screenshot 2024-04-09 at 15-26-55 Introduction to Active Directory](https://github.com/kiro6/penetration-testing-notes/assets/57776872/4c8a6038-339e-41fd-b2bc-c47abaaef6f9)

#### **AD LDAP Authentication**
1. **Simple Authentication:** This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a username and password create a BIND request to authenticate to the LDAP server.

2. **SASL Authentication:** The Simple Authentication and Security Layer (SASL) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP.




**auth protocols table**
| Hash/Protocol | Cryptographic Technique       | Mutual Authentication | Message Type      | Trusted Third Party              |
|---------------|-------------------------------|-----------------------|-------------------|---------------------------------|
| NTLM          | Symmetric key cryptography   | No                    | Random number     | Domain Controller               |
| NTLMv1        | Symmetric key cryptography   | No                    | MD4 hash, random number | Domain Controller               |
| NTLMv2        | Symmetric key cryptography   | No                    | MD4 hash, random number | Domain Controller               |
| Kerberos      | Symmetric key cryptography & asymmetric cryptography | Yes   | Encrypted ticket using DES, MD5 | Domain Controller/Key Distribution Center (KDC) |


### Kerberos
Kerberos Key Distribution Center (KDC): Domain Controllers in Active Directory Domain Services (AD DS) include a Kerberos Key Distribution Center (KDC).

#### **Kerberos Authentication Process**
1. The user logs on, and their password is converted to an NTLM hash, which is used to encrypt the TGT ticket. This decouples the user's credentials from requests to resources.
2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.
3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.
4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.
5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ).
6. both TGT and TGS  stored in memory 
![Screenshot 2024-04-09 at 15-20-16 Introduction to Active Directory](https://github.com/kiro6/penetration-testing-notes/assets/57776872/bab56808-5196-4d76-97ca-44920c058794)


 For domain-joined computers, users typically log in using their domain credentials. Upon successful login, the system automatically obtains a TGT from the KDC using the user's credentials.




### LM
- LAN Manager (LM or LANMAN) hashes are the oldest password storage mechanism used by the Windows operating system
- LM hashes are stored in the SAM or NTDS.DIT database on Windows hosts or Domain Controllers, respectively.
- These hashes are limited to 14 characters, not case sensitive, and converted to uppercase before hashing, making them vulnerable to brute force attacks.


### NTHash (NTLM)
- NT LAN Manager (NTLM) hashes are used on modern Windows systems.
- **It is a challenge-response authentication protocol and uses three messages to authenticate:**
  1. The client sends a message to the server indicating its intention to authenticate using NTLM.
  2. The server responds with a challenge, which is a random number.
  3. The client encrypts this challenge using the MD4 hash of the user's password. This encrypted result, along with the username and domain name, is sent back to the server.
  4. The server uses the same method to encrypt the challenge and compares the result with what the client sent. If they match, authentication is successful

- These hashes are stored locally in the SAM database or the NTDS.DIT database file on a Domain Controller.

![Screenshot 2024-04-09 at 20-01-32 Introduction to Active Directory](https://github.com/kiro6/penetration-testing-notes/assets/57776872/115664df-b244-4990-8479-8d38e5f7f804)


- The protocol has two hashed password values to choose from to perform authentication:
  - the LM hash (as discussed above) 
  - the NT hash, which is the MD4 hash of the little-endian UTF-16 value of the password. The algorithm can be visualized as: MD4(UTF-16-LE(password)).
  - Neither LANMAN nor NTLM uses a salt.

- NTLM is also vulnerable to the pass-the-hash attack.
```bash
netexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2
```

### NTLMv1 (Net-NTLMv1)
NTLMv1 is the first version of the NTLM authentication protocol.

**V1 Challenge & Response Algorithm**
```
C = 8-byte server challenge, random
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1,C) | DES(K2,C) | DES(K3,C)
```

### NTLMv2 (Net-NTLMv2)
- NTLMv2 is an enhanced authentication protocol introduced as a stronger alternative to NTLMv1.


**V2 Challenge & Response Algorithm**
```bash
SC = 8-byte server challenge, random
CC = 8-byte client challenge, random
CC* = (X, time, CC2, domain name)
v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
response = LMv2 | CC | NTv2 | CC*
```
