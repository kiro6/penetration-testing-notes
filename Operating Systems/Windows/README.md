# Content 
- [Structure](#structure)
- [User and Group Management](#account--user-and-group-management)
- [CMD and PowerShell](#cmd-and-powerShell)
- [Windows Registry](#windows-registry)
- [Windows Event Log](#windows-event-log)
- [File System](#file-system)
- [Windows Services](#windows-services)
- [Windows Management Instrumentation (WMI)](#windows-management-instrumentation-wmi)
- [Security](#Security)
  - [Windows security model](#windows-security-model)
  - [Security identifiers](#security-identifiers)
  - [Access Tokens](#access-tokens)
  - [Access Rights](#access-rights)
  - [Privileges](#privileges)
  - [User Account Control (UAC)](#user-account-control-uac)
- [Pipes](#pipes)


# Structure

## C:\

| Directory            | Function|
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Perflogs             | Can hold Windows performance logs but is empty by default.|
| Program Files        | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.|
| Program Files (x86)  | 32-bit and 16-bit programs are installed here on 64-bit editions of Windows.|
| ProgramData          | This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.|
| Users                | This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.|
| Windows              | The majority of the files required for the Windows operating system are contained here.|
| System, System32, SysWOW64 | Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.                                              |
| WinSxS               | The Windows Component Store contains a copy of all Windows components, updates, and service packs.       |




## C:\Windows\System32
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| \winevt\logs         | Windows Event Logs are stored in it with the file extension .evtx  | 

## C:\Windows\
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Temp                 | Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. Useful for dropping files as a low-privilege user on the system.  | 


## C:\Users\
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Default              | This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.|
| Public               | This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.|


## C:\Users\user
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AppData | Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData)..   |

## C:\Users\user\AppData
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Roaming | The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. |
| Local | The Local folder is specific to the computer itself and is never synchronized across the network. |
| LocalLow | LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode. |

## C:\Users\user\AppData\Local
| Directory            | Function |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Temp | Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. Useful when the attacker gains control of a local/domain joined user account. | 


# Account , User and Group Management
User accounts are a way for personnel to access and use a host's resources. In certain circumstances, the system will also utilize a specially provisioned user account to perform actions.

#### Account Types
- Service Accounts
- Built-in accounts
- Local users
- Domain users

#### Built-in accounts
| Account           | Description                                                                                                     |
| ----------------- | --------------------------------------------------------------------------------------------------------------- |
| Administrator     | This account is used to accomplish administrative tasks on the local host.                                      |
| SYSTEM             | Used by the operating system and services running under Windows for internal processes and tasks. It's an internal account that doesn't show up in User Manager, and it can't be added to any groups.               |
| Default Account    | The default account is used by the system for running multi-user auth apps like the Xbox utility.                |
| Guest Account      | This account is a limited rights account that allows users without a normal user account to access the host. It is disabled by default and should stay that way. |
| WDAGUtility Account| This account is in place for the Defender Application Guard, which can sandbox application sessions.             |


#### Local Accounts Doc
[Local Accounts Doc](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)



# CMD and PowerShell

check [CMD and PowerShell notes in my repo](https://github.com/kiro6/penetration-testing-notes/tree/main/Scripting/powershell%20and%20CMD)



# Windows Registry
- the Registry can be considered a hierarchal tree that contains two essential elements: **keys** and **values**. 
- This tree stores all the required information for the operating system and the software installed to run under subtrees (think of them as branches of a tree). 
- This information can be anything from settings to installation directories to specific options and values that determine how everything functions.



### Registry Key

#### registry-hives
- they are high-level structures in the Windows Registry that organize and contain multiple keys, subkeys, and values.
- The term "hive" is used to describe these top-level containers that hold different sections of the registry
- [registry hives doc](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)


| Registry Hive            | Description                                                                                                           |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------|
| HKEY_CLASSES_ROOT (HKCR) | This hive contains information about file associations, shortcuts, and OLE (Object Linking and Embedding) object classes. |
| HKEY_CURRENT_USER (HKCU) | This hive contains configuration information for the user currently logged in. It includes user-specific settings such as desktop configurations and environment variables. |
| HKEY_LOCAL_MACHINE (HKLM)| This hive contains configuration information for the local machine. It includes system-wide settings such as hardware configurations, installed software, and system policies. |
| HKEY_USERS (HKU)         | This hive contains user profiles information for all users who have logged into the system.                              |
| HKEY_CURRENT_CONFIG      | This hive contains information about the current hardware configuration. It is a link to a specific key in the HKLM hive. |
| HKEY_DYN_DATA            | This hive contains information about plug-and-play devices and is used by the operating system to configure dynamic hardware. |

#### registry hives files extension 
| Extension | Description                                                                                                                                                                                         |
|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| none      | A complete copy of the hive data.                                                                                                                                                                  |
| .alt      | A backup copy of the critical HKEY_LOCAL_MACHINE\System hive. Only the System key has an .alt file.                                                                                              |
| .log      | A transaction log of changes to the keys and value entries in the hive.                                                                                                                            |
| .sav      | A backup copy of a hive. Windows Server 2003 and Windows XP/2000: Copies of the hive files as they looked at the end of the text-mode stage in Setup. Setup has two stages: text mode and graphics mode. The hive is copied to a .sav file after the text-mode stage of setup to protect it from errors that might occur if the graphics-mode stage of setup fails. If setup fails during the graphics-mode stage, only the graphics-mode stage is repeated when the computer is restarted; the .sav file is used to restore the hive data. |

### Registry value
- Values represent data in the form of objects that pertain to that specific Key. 
- These values consist of a name, a type specification, and the required data to identify what it's for.
- [Registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)





# Windows Event Log
- Event Logging as defined by Microsoft:
"...provides a standard, centralized way for applications (and the operating system) to record important software and hardware events."
- The Windows Event Log is handled by the EventLog services
- On a Windows system, the service's display name is `Windows Event Log`, and it runs inside the service host process svchost.exe. It is set to start automatically at system boot by default.

#### Event Log Categories 

| Log Category       | Log Description                                                                                              |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| System Log         | The system log contains events related to the Windows system and its components. A system-level event could be a service failing at startup.                   |
| Security Log       | Self-explanatory; these include security-related events such as failed and successful logins, and file creation/deletion. These can be used to detect various types of attacks that we will cover in later modules. |
| Application Log    | This stores events related to any software/application installed on the system. For example, if Slack has trouble starting it will be recorded in this log.              |
| Setup Log          | This log holds any events that are generated when the Windows operating system is installed. In a domain environment, events related to Active Directory will be recorded in this log on domain controller hosts. |
| Forwarded Events   | Logs that are forwarded from other hosts within the same network.                                              |

#### Event Log Types

| Type of Event    | Event Description |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Error            | Indicates a major problem, such as a service failing to load during startup, has occurred. |
| Warning          | A less significant log but one that may indicate a possible problem in the future. One example is low disk space. A Warning event will be logged to note that a problem may occur down the road. A Warning event is typically when an application can recover from the event without losing functionality or data. |
| Information      | Recorded upon the successful operation of an application, driver, or service, such as when a network driver loads successfully. Typically not every desktop application will log an event each time they start, as this could lead to a considerable amount of extra "noise" in the logs. |
| Success Audit    | Recorded when an audited security access attempt is successful, such as when a user logs on to a system. |
| Failure Audit    | Recorded when an audited security access attempt fails, such as when a user attempts to log in but types their password in wrong. Many audit failure events could indicate an attack, such as Password Spraying. |


#### Event Severity Levels
| Severity Level | Level # | Description                                                                                                                    |
|----------------|---------|--------------------------------------------------------------------------------------------------------------------------------|
| Verbose        | 5       | Progress or success messages.                                                                                                 |
| Information    | 4       | An event that occurred on the system but did not cause any issues.                                                            |
| Warning        | 3       | A potential problem that a sysadmin should dig into.                                                                           |
| Error          | 2       | An issue related to the system or service that does not require immediate attention.                                          |
| Critical       | 1       | This indicates a significant issue related to an application or a system that requires urgent attention by a sysadmin, and if not addressed, could lead to system or application instability. |

#### Elements of a Windows Event Log
- **Log name:** As discussed above, the name of the event log where the events will be written. By default, events are logged for system, security, and applications.
- **Event date/time:** Date and time when the event occurred
- **Task Category:** The type of recorded event log
- **Event ID:** A unique identifier for sysadmins to identify a specific logged event
- **Source:** Where the log originated from, typically the name of a program or software application
- **Level:** Severity level of the event. This can be information, error, verbose, warning, critical
- **User:** Username of who logged onto the host when the event occurred
- **Computer:** Name of the computer where the event is logged

#### lists 
- [searchable database of Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [list includes key events that are recommended to be monitored for to look for signs of a compromise](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)



## File System
NTFS (New Technology File System) is the default Windows file system since Windows NT 3.1.


- [icacls commands](https://ss64.com/nt/icacls.html)

```powershell
icacls c:\Users
c:\Users NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)
         BUILTIN\Users:(RX)
         BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
         Everyone:(RX)
         Everyone:(OI)(CI)(IO)(GR,GE)
```


- **Inheritance settings are:**

| Inheritance Setting | Description                                                    |
|---------------------|----------------------------------------------------------------|
| OI                  | Object inherit - Applies to this folder and files only. No inheritance to subfolders. |
| CI                  | Container inherit - Applies to this folder and subfolders.      |
| IO                  | Inherit only - The ACE does not apply to the current file/directory. |
| NP                  | Do not propagate inherit - The ACE is not inherited by child objects. |
| I                   | Permission inherited from parent container.                     |

- **Basic access permissions**

| Access Right | Description                         |
|--------------|-------------------------------------|
| F            | Full access                         |
| D            | Delete access                       |
| N            | No access                           |
| M            | Modify access                       |
| RX           | Read and execute access             |
| R            | Read-only access                    |
| W            | Write-only access                   |




### NTFS vs. Share Permissions

- **Share permissions**

| Permission    | Description                                                                                              |
|---------------|----------------------------------------------------------------------------------------------------------|
| Full Control  | Users are permitted to perform all actions given by Change and Read permissions as well as change permissions for NTFS files and subfolders. |
| Change        | Users are permitted to read, edit, delete, and add files and subfolders.                                 |
| Read          | Users are allowed to view file and subfolder contents.                                                    |




## Windows Services

- Windows services are managed via the Service Control Manager (SCM) system, accessible via the services.msc MMC add-in.
- Windows has three categories of services:
  - Local Services
  - Network Services
  - System Services
- Services can usually only be created, modified, and deleted by users with administrative privileges.
- Misconfigurations around service permissions are a common privilege escalation vector on Windows systems.


### In Windows, we have some critical system services that cannot be stopped and restarted without a system restart.

| Service                | Description                                                                                              |
|------------------------|----------------------------------------------------------------------------------------------------------|
| smss.exe               | Session Manager SubSystem. Responsible for handling sessions on the system.                              |
| csrss.exe              | Client Server Runtime Process. The user-mode portion of the Windows subsystem.                            |
| wininit.exe            | Starts the Wininit file .ini file that lists all of the changes to be made to Windows during restart.    |
| logonui.exe            | Used for facilitating user login into a PC.                                                              |
| lsass.exe              | The Local Security Authentication Server verifies the validity of user logons.                             |
| services.exe           | Manages the operation of starting and stopping services.                                                 |
| winlogon.exe           | Responsible for handling the secure attention sequence, loading user profiles, and locking the computer. |
| System                 | A background system process that runs the Windows kernel.                                                 |
| svchost.exe (RPCSS)   | Manages system services using Remote Procedure Call (RPC) Service (RPCSS).                                |
| svchost.exe (Dcom/PnP) | Manages system services using Distributed Component Object Model (DCOM) and Plug and Play (PnP) services. |


### Local Security Authority Subsystem Service (LSASS)
- lsass.exe is the process that is responsible for enforcing the security policy on Windows systems.
- LSASS is also responsible for user account password changes.
- LSASS is an extremely high-value target as several tools exist to extract both cleartext and hashed credentials stored in memory by this process.

### Sysinternals Tools
The SysInternals Tools suite is a set of portable Windows applications that can be used to administer Windows systems

```powershell
\\live.sysinternals.com\tools\procdump.exe -accepteula  # online
procdump.exe -accepteula                                # local
```


## Windows Management Instrumentation (WMI)
- WMI is a subsystem of PowerShell that provides system administrators with powerful tools for system monitoring. 
- The goal of WMI is to consolidate device and application management across corporate networks.

**Some of the uses for WMI are:**

- Status information for local/remote systems
- Configuring security settings on remote machines/-
- Setting and changing user and group permissions
- Setting/modifying system properties
- Code execution
- Scheduling processes
- Setting up logging

```cmd
wmic /?
```



# Security
## Windows security model
Windows security model following key components:
- Security identifiers (SIDs)
- Access tokens
- Security descriptors
- Access Control Lists (ACLs)
- Privileges




## Security identifiers   
[documntation](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/windows-security-model)
- operating system internally refers to accounts and processes that run in the security context of the account by using their SIDs. 
- For domain accounts, the SID of a security principal is created by concatenating the SID of the domain with a relative identifier (RID) for the account.


![Screenshot_31](https://github.com/kiro6/penetration-testing-notes/assets/57776872/8ca13621-c4e7-419f-9f32-b1084244a18b)
- SIDs are unique within their scope (domain or local), and they're never reused.



### SID identifier authority

| Authority                   | ID | SID Prefix | Description                                                                                               |
|-----------------------------|----|------------|-----------------------------------------------------------------------------------------------------------|
| SECURITY_NULL_SID_AUTHORITY | 0  | S-1-0      | Represents an empty or null security identifier. It's typically used for placeholder or special purposes. |
| SECURITY_WORLD_SID_AUTHORITY| 1  | S-1-1      | Represents the "Everyone" group, which includes all users, even those from outside the local domain.      |
| SECURITY_LOCAL_SID_AUTHORITY| 2  | S-1-2      | Represents local security identifiers. These SIDs are used for built-in local groups and users on a system.|
| SECURITY_CREATOR_SID_AUTHORITY | 3 | S-1-3   | Represents SIDs that are dynamically generated to represent the creator/owner of an object. These SIDs are used to grant permissions based on object ownership. |
| SECURITY_NT_AUTHORITY       | 5  | S-1-5      | Represents the Windows NT authority. SIDs generated using this authority are the most common and are used for domain accounts, built-in groups, and security principals in Windows environments. |



### SID components



`S-R-X-Y1-Y2-Yn-1-Yn`

| Comment | Description                                         |
| ------- | --------------------------------------------------- |
| S       | Indicates that the string is a SID                 |
| R       | Indicates the revision level                        |
| X       | Indicates the identifier authority value            |
| Y       | Represents a series of subauthority values, where n is the number of values |


**Example 1:** the SID for the built-in Administrators group is represented in standardized SID notation as the following string:

```
S-1-5-32-544
```

This SID has four components:
- A revision level (1)
- An identifier authority value (5, NT Authority)
- A domain identifier (32, Builtin)
- A relative identifier (544, Administrators)


**Example 2:** 
```powershell
PS C:\htb> whoami /user

USER INFORMATION
----------------

User Name           SID
=================== =============================================
ws01\bob S-1-5-21-674899381-4069889467-2080702030-1002
```

| Number | Meaning           | Description                                                                                      |
|--------|-------------------|--------------------------------------------------------------------------------------------------|
| S      | SID               | Identifies the string as a SID.                                                                 |
| 1      | Revision Level    | To date, this has never changed and has always been 1.                                           |
| 5      | Identifier-authority | A 48-bit string that identifies the authority (the computer or network) that created the SID. |
| 21     | Subauthority1     | This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account. |
| 674899381-4069889467-2080702030 | Subauthority2 | Tells us which computer (or domain) created the number.                                           |
| 1002   | Subauthority3     | The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group. |



### universal well-known SIDs 

[well-known SIDs](
https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers)

![Screenshot 2023-11-30 101718](https://github.com/kiro6/penetration-testing-notes/assets/57776872/748726c4-217d-4348-998e-f31647da1845)

### RID 
- RIDs are used in the Security Identifier (SID) structure to uniquely identify security principals such as users, groups, and computers within a Windows domain. 
- RIDs are generated by the domain controller and are unique within the domain.
- A security principal in the context of Windows security refers to any entity that can be authenticated by the operating system's security mechanisms and can be assigned permissions or rights to access resources.

**security principals:**



- User accounts: Individual users who can log in to the system.
- Group accounts: Collections of user accounts, which can be used to simplify permission management by assigning permissions to the group rather than to individual users.
- Computer accounts: Computers that are members of a domain or workgroup.
- Service accounts: Special accounts used by services and applications to access system resources.
- Built-in accounts: Default accounts created by the system, such as the Administrator account or Guest account.


[check defntion here](https://en.wikipedia.org/wiki/Relative_identifier)


### SID and RID
SID  for domain RID for security principal 

#### SID for Domain: 
This consists of a domain's unique identifier, also known as the Domain Identifier Authority, and it uniquely identifies the domain within the Windows environment. It is typically in the form of a Security Identifier SID: S-1-5-21-{domain}-...

#### RID for Security Principal: 
This is a number that uniquely identifies a security principal within the domain. It's appended to the domain SID to create a unique identifier for that specific security principal. The RID distinguishes users, groups, and other security principals within the domain. It's represented as a number in the SID structure.

***For example*** 

if we have a user named `John` in a domain with the `SID S-1-5-21-{domain}`, `John` will have a SID that looks like `S-1-5-21-{domain}-1234`, where `1234` is the RID assigned to the `John` user within that domain.



## Access tokens
[documntation](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- An access token is an object that describes the security context of a process or thread.
- Every process executed on behalf of this user has a copy of this access token.
- When a user logs on, the system verifies the user's password by comparing it with information stored in a security database in SAM. If the password is authenticated, the system produces an access token

- Access tokens contain the following information:
   - The security identifier (SID) for the user's account
   - SIDs for the groups of which the user is a member
   - A logon SID that identifies the current logon session
   - A list of the privileges held by either the user or the user's groups
   - An owner SID
   - The SID for the primary group
   - The default DACL that the system uses when the user creates a securable object without specifying a security descriptor
   - The source of the access token
   - Whether the token is a primary or impersonation token
   - An optional list of restricting SIDs
   - Current impersonation levels
   - Other statistics

- When an **administrator** logs on, two separate access tokens are created for the user: a **standard user access token(Filtered Token)** and an **administrator access token(Elevated Token)**.
  - A user that is a member of the Administrators group can sign in, browse the Web, and read e-mail while using a standard user access token.
  - When the administrator needs to perform a task that requires the administrator access token, Windows automatically prompts the user for approval.
  - This prompt is called an elevation prompt, and its behavior can be configured via policy or registry. 




## Access Rights

### Access Control List (ACL)
An Access Control List (ACL) is the ordered collection of Access Control Entries (ACEs) that apply to an object.

### Access Control Entries (ACEs)
Each Access Control Entry (ACE) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.


#### ACEs

| ACE Type            | Description                                                                                             |
|---------------------|---------------------------------------------------------------------------------------------------------|
| Access denied ACE   | Used within a DACL to show that a user or group is explicitly denied access to an object                |
| Access allowed ACE  | Used within a DACL to show that a user or group is explicitly granted access to an object               |
| System audit ACE    | Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred |

Each ACE is made up of the following four components:
- A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
- A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
- An [access mask - rights](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)  which is a 32-bit value that defines the rights granted to an object
- The security identifier (SID) of the user/group that has access to the object (or principal name graphically)


just represntation in json
```yaml
ACE {
    Type: Access allowed
    Flags: Object Inherit, Container Inherit
    Access Mask: 0x001200A9 (Read, Write, Execute)
    SID: S-1-5-21-3623811015-3361044348-30300820-1013
}

```

ACE has the following structure: (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute) ) 
```
get-Acl -Path c:\ | Format-List

icacls c:\

cacls c:\

(Get-Acl c:\).Sddl
```

- [microsoft learn ace strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings) 
- [microsoft learn sid strings](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings)  
- [ACL meanings in services](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/)

Allowed ace_types


![Screenshot 2024-06-18 at 11-37-36 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/cc775733-18f6-425c-bb7c-8f1e8a279387)

Allowed ace_flags


![Screenshot 2024-06-18 at 11-37-40 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/551a1281-a1e5-465b-bbef-eef58debce3c)

Generic Rights


![Screenshot 2024-06-18 at 11-37-58 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/da64e040-a1c3-4d53-a7c2-10081df6479b)

Specific File Rights


![Screenshot 2024-06-18 at 11-38-03 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/419699f1-a7b1-4d4e-b508-fe64afa6d53b)

Specific Registry Rights


![Screenshot 2024-06-18 at 11-38-05 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/907ab05c-2f2a-49a4-b9e1-af3420820291)

Integrity Labels


![Screenshot 2024-06-18 at 11-38-10 Access Control Understanding Windows File And Registry Permissions](https://github.com/kiro6/penetration-testing-notes/assets/57776872/def92da9-8ca0-4994-b9e5-738e4f058867)


### Discretionary Access Control List (DACL)
DACLs define which security principles are granted or denied access to an object; it contains a list of ACEs. When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access. If an object does NOT have a DACL, then the system will grant full access to everyone, but if the DACL has no ACE entries, the system will deny all access attempts. ACEs in the DACL are checked in sequence until a match is found that allows the requested rights or until access is denied.

- is type of ACL

### System Access Control Lists (SACL)
Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

- is type of ACL

## Privileges
- Privileges are special permissions granted to user accounts or security principals that allow them to perform specific system-level operations.
- Privileges are typically managed through the `Local Security Policy (secpol.msc)` or `Group Policy (gpedit.msc)` under `User Rights Assignment`.
- [User Rights Assignment](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment)


| Setting Constant              | Setting Name                                        | Standard Assignment                          | Description                                                                                                                                                                                                                               |
|-------------------------------|----------------------------------------------------|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SeNetworkLogonRight           | Access this computer from the network              | Administrators, Authenticated Users          | Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+.                                                                                            |
| SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services       | Administrators, Remote Desktop Users         | This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server. |
| SeBackupPrivilege             | Back up files and directories                      | Administrators                               | This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.                                                                        |
| SeSecurityPrivilege           | Manage auditing and security log                   | Administrators                               | This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer. |
| SeTakeOwnershipPrivilege      | Take ownership of files or other objects           | Administrators                               | This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads.                |
| SeDebugPrivilege              | Debug programs                                     | Administrators                               | This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components. |
| SeImpersonatePrivilege        | Impersonate a client after authentication          | Administrators, Local Service, Network Service, Service | This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user.                                                                                               |
| SeLoadDriverPrivilege         | Load and unload device drivers                     | Administrators                               | This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code.                 |
| SeRestorePrivilege            | Restore files and directories                      | Administrators                               | This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object.                  |


## User Account Control (UAC)
- [How User Account Control works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [User Account Control settings and configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=intune)

### UAC Internals
1) The user requests to run an application as administrator.
2) A ShellExecute API call is made using the runas verb.
3) The request gets forwarded to Appinfo(Application Information Service) to handle elevation.
4) The application manifest is checked to see if AutoElevation is allowed .
5) Appinfo executes consent.exe, which shows the UAC prompt on a secure desktop. A secure desktop is simply a separate desktop that isolates processes from whatever is running in the actual user's desktop to avoid other processes from tampering with the UAC prompt in any way.
6) If the user gives consent to run the application as administrator, the Appinfo service will execute the request using a user's Elevated Token. Appinfo will then set the parent process ID of the new process to point to the shell from which elevation was requested.

![Screenshot 2024-07-23 at 10-30-20 TryHackMe Bypassing UAC](https://github.com/user-attachments/assets/f1bc9939-cb49-45fd-9cb2-608047ea9f00)





## Mandatory Integrity Control
- [Mandatory Integrity Control doc](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- `Mandatory Integrity Control (MIC)`, which is a mechanism that allows differentiating users, processes and resources by assigning an `Integrity Level (IL)` to each of them.
- MIC takes precedence over regular Windows DACLs, so you may be authorized to access a resource according to the DACL, but it won't matter if your IL isn't high enough.


| Integrity Level | Use                                                                                     |
|-----------------|-----------------------------------------------------------------------------------------|
| Low             | Generally used for interaction with the Internet (i.e., Internet Explorer). Has very limited permissions. |
| Medium          | Assigned to standard users and Administrators' filtered tokens.                        |
| High            | Used by Administrators' elevated tokens if UAC is enabled. If UAC is disabled, all administrators will always use a high IL token. |
| System          | Reserved for system use.                                                                 |



# Pipes

- Pipes are used for communication between two applications or processes using shared memory.
- Pipes are essentially files stored in memory that get cleared out after being read.
- There are two types of pipes
  - named pipes - An example of a named pipe is `\\.\PipeName\\ExampleNamedPipeServer`
  - anonymous pipes 
- Windows systems use a client-server implementation for pipe communication. In this type of implementation, the process that creates a named pipe is the server, and the process communicating with the named pipe is the client.
- Every active connection to a named pipe server results in the creation of a new named pipe. These all share the same pipe name but communicate using a different data buffer.
- Named pipes can communicate
  - using half-duplex, or a one-way channel with the client only being able to write data to the server
  - duplex, which is a two-way communication channel that allows the client to write data over the pipe, and the server to respond back with data over that pipe
