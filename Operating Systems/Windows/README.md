# Content 
- [Structure](#structure)
- [Security](#Security)
  - [Windows security model](#windows-security-model)
  - [Security identifiers](#security-identifiers)
  - [Access Tokens](#access-tokens)
- [Windows Services](#windows-services)


# Structure
| Directory            | Function                                                                                                                                                                                                                                         |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Perflogs             | Can hold Windows performance logs but is empty by default.                                                                                                                                                                                       |
| Program Files        | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.                                                                                                                |
| Program Files (x86)  | 32-bit and 16-bit programs are installed here on 64-bit editions of Windows.                                                                                                                                                                     |
| ProgramData          | This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.                                                                   |
| Users                | This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.                                                                                                                        |
| Default              | This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.                                                                                      |
| Public               | This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.                                              |
| AppData              | Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode. |
| Windows              | The majority of the files required for the Windows operating system are contained here.                                                                                                                                                           |
| System, System32, SysWOW64 | Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.                                              |
| WinSxS               | The Windows Component Store contains a copy of all Windows components, updates, and service packs.                                                                                                                                               |






# Security
Windows security model following key components:
- Security identifiers (SIDs)
- Access tokens
- Security descriptors
- Access Control Lists (ACLs)
- Privileges



## Windows security model

## Security identifiers   
[documntation](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/windows-security-model)
- operating system internally refers to accounts and processes that run in the security context of the account by using their SIDs. 
- For domain accounts, the SID of a security principal is created by concatenating the SID of the domain with a relative identifier (RID) for the account.


![Screenshot_31](https://github.com/kiro6/penetration-testing-notes/assets/57776872/8ca13621-c4e7-419f-9f32-b1084244a18b)
- SIDs are unique within their scope (domain or local), and they're never reused.


### SID components

`S-R-X-Y1-Y2-Yn-1-Yn`

| Comment | Description                                         |
| ------- | --------------------------------------------------- |
| S       | Indicates that the string is a SID                 |
| R       | Indicates the revision level                        |
| X       | Indicates the identifier authority value            |
| Y       | Represents a series of subauthority values, where n is the number of values |


**Examples:** the SID for the built-in Administrators group is represented in standardized SID notation as the following string:

```
S-1-5-32-544
```

This SID has four components:
- A revision level (1)
- An identifier authority value (5, NT Authority)
- A domain identifier (32, Builtin)
- A relative identifier (544, Administrators)


**Examples:** The following example represents the SID for the Domain Admins group in the Contoso, Ltd. domain (Contoso\Domain Admins):
```
S-1-5-21-1004336348-1177238915-682003330-512
```

The SID for Contoso\Domain Admins has:
- A revision level (1)
- An identifier authority (5, NT Authority)
- A domain identifier (21-1004336348-1177238915-682003330, Contoso)
- A relative identifier (512, Domain Admins)


### universal well-known SIDs 
![Screenshot 2023-11-30 101718](https://github.com/kiro6/penetration-testing-notes/assets/57776872/748726c4-217d-4348-998e-f31647da1845)


### predefined identifier authority constants

| Identifier Authority                  | Value | SID String Prefix |
|----------------------------------------|-------|-------------------|
| SECURITY_NULL_SID_AUTHORITY           | 0     | S-1-0             |
| SECURITY_WORLD_SID_AUTHORITY          | 1     | S-1-1             |
| SECURITY_LOCAL_SID_AUTHORITY          | 2     | S-1-2             |
| SECURITY_CREATOR_SID_AUTHORITY        | 3     | S-1-3             |
| SECURITY_NT_AUTHORITY                 | 5     | S-1-5             |
| SECURITY_AUTHENTICATION_AUTHORITY     | 18    | S-1-18            |


**The SECURITY_NT_AUTHORITY (S-1-5):** predefined identifier authority produces SIDs that aren't universal and are meaningful only in installations of the Windows operating systems

### some of installations of the Windows operating systems well-known SIDs
| SID           | Name                   | 
|-------------- |------------------------| 
| S-1-5-18      | System (or LocalSystem)|
| S-1-5-19      | NT Authority (LocalService)|
| S-1-5-20      | Network Service        |
| S-1-5-domain-500 | Administrator      |
| S-1-5-6       | Service                |
| S-1-5-2       | Network                |

## Access tokens
[documntation](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- An access token is an object that describes the security context of a process or thread.
- Every process executed on behalf of this user has a copy of this access token.
- When a user logs on, the system verifies the user's password by comparing it with information stored in a security database. If the password is authenticated, the system produces an access token

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


## NTFS
NTFS (New Technology File System) is responsible for handling file and folder permissions in the Windows operating system.
### NTFS Basic permissions

| Permission Type          | Description                                                                                                      |
|--------------------------|------------------------------------------------------------------------------------------------------------------|
| Full Control             | Allows reading, writing, changing, deleting of files/folders.                                                    |
| Modify                   | Allows reading, writing, and deleting of files/folders.                                                           |
| List Folder Contents     | Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission. |
| Read and Execute         | Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission. |
| Write                    | Allows for adding files to folders and subfolders and writing to a file.                                           |
| Read                     | Allows for viewing and listing of folders and subfolders and viewing a file's contents.                             |
| Traverse Folder          | This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory in this example c:\users\bsmith\documents\webapps\backups\backup_02042020.zip but with Traverse Folder permissions applied, they can access the backup archive. |


### NTFS special permissions

| Permission                         | Description                                                                                                          |
|------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Full control                       | Users are permitted or denied permissions to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all permitted folders. |
| Traverse folder / execute file      | Users are permitted or denied permissions to access a subfolder within a directory structure even if the user is denied access to contents at the parent folder level. Users may also be permitted or denied permissions to execute programs. |
| List folder/read data               | Users are permitted or denied permissions to view files and folders contained in the parent folder. Users can also be permitted to open and view files. |
| Read attributes                    | Users are permitted or denied permissions to view basic attributes of a file or folder. Examples of basic attributes: system, archive, read-only, and hidden. |
| Read extended attributes           | Users are permitted or denied permissions to view extended attributes of a file or folder. Attributes differ depending on the program. |
| Create files/write data             | Users are permitted or denied permissions to create files within a folder and make changes to a file. |
| Create folders/append data          | Users are permitted or denied permissions to create subfolders within a folder. Data can be added to files but pre-existing content cannot be overwritten. |
| Write attributes                   | Users are permitted or denied to change file attributes. This permission does not grant access to creating files or folders. |
| Write extended attributes          | Users are permitted or denied permissions to change extended attributes on a file or folder. Attributes differ depending on the program. |
| Delete subfolders and files         | Users are permitted or denied permissions to delete subfolders and files. Parent folders will not be deleted. |
| Delete                             | Users are permitted or denied permissions to delete parent folders, subfolders, and files. |
| Read permissions                   | Users are permitted or denied permissions to read permissions of a folder. |
| Change permissions                 | Users are permitted or denied permissions to change permissions of a file or folder. |
| Take ownership                     | Users are permitted or denied permission to take ownership of a file or folder. The owner of a file has full permissions to change any permissions. |


### inheritance rights:
- **(OI) Object Inherit:**           This folder and files. (No inheritance to subfolders)
- **(CI) Container Inherit:**        This folder and subfolders.
- **(IO) Inherit Only:**             The ACE does not apply to the current file/directory.
- **(I) Permission Inherited:**      Permission on the current object is inherited from its parent container.
- **(NP) Don't Propagate Inherit:**  Prevents the inheritance of permissions to child objects.

### simple rights:
- D : Delete access
- F : Full access (Edit_Permissions+Create+Delete+Read+Write)
- N : No access
- M : Modify access (Create+Delete+Read+Write)
- RX : Read and eXecute access
- R : Read-only access
- W : Write-only access
```powershell
icacls c:\Users
c:\Users NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)
         BUILTIN\Users:(RX)
         BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
         Everyone:(RX)
         Everyone:(OI)(CI)(IO)(GR,GE)
```

# Windows Services

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
