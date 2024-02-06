# Content 
- [FTP](#ftp)
- [SMB](#smb)

## FTP
File Transfer Protocol
### port used  
- 21/TCP for control channel
- 20/TCP for data channel in active mode
- for passice mode the server tell the client which port to connect
### Dangerous Settings
| Setting                      | Description                                              |
|------------------------------|----------------------------------------------------------|
| anonymous_enable=YES         | Allowing anonymous login?                               |
| anon_upload_enable=YES       | Allowing anonymous to upload files?                     |
| anon_mkdir_write_enable=YES | Allowing anonymous to create new directories?           |
| no_anon_password=YES         | Do not ask anonymous for password?                      |
| anon_root=/home/username/ftp| Directory for anonymous.                                 |
| write_enable=YES             | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |

### Footprinting the Service
- nmap 
```bash
sudo nmap -sV -p21 -sC -A 10.129.14.136

sudo nmap -sV -p21 -sC -A 10.129.14.136 --script ftp*
```
### Service Interaction
- connect
```bash
ftp 10.129.14.136

nc -nv 10.129.14.136 21

telnet 10.129.14.136 21

openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
- commands

| Command | Description                                                                                               |
|---------|-----------------------------------------------------------------------------------------------------------|
| connect | Sets the remote host, and optionally the port, for file transfers.                                         |
| get     | Transfers a file or set of files from the remote host to the local host.                                     |
| put     | Transfers a file or set of files from the local host onto the remote host.                                   |
| quit    | Exits tftp.                                                                                                |
| status  | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| verbose | Turns verbose mode, which displays additional information during file transfer, on or off.                  |

- Download All Available Files
```bash
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```
## SMB
Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network

- `CIFS` was used as the same as SMB but now it's old and work on the same ports as SMB

### port used  
-  `OLD` 137, 138, and 139 TCP
-  `NEW` 445 TCP

### Dangerous Settings
| Setting             | Description                                                   |
|---------------------|---------------------------------------------------------------|
| browseable = yes    | Allow listing available shares in the current share?          |
| read only = no      | Forbid the creation and modification of files?                |
| writable = yes      | Allow users to create and modify files?                       |
| guest ok = yes      | Allow connecting to the service without using a password?     |
| enable privileges = yes | Honor privileges assigned to specific SID?                 |
| create mask = 0777 | What permissions must be assigned to the newly created files? |
| directory mask = 0777 | What permissions must be assigned to the newly created directories? |
| logon script = script.sh | What script needs to be executed on the user's login?     |
| magic script = script.sh | Which script should be executed when the script gets closed? |
| magic output = script.out | Where the output of the magic script needs to be stored?   |


### Footprinting the Service
- nmap
```bash
 sudo nmap 10.129.14.128 -sV -sC -p139,445
```
- 
### Service Interaction
```bash
rpcclient -U "" 10.129.14.128
```
- rpcclient commands

| Query               | Description                                                   |
|---------------------|---------------------------------------------------------------|
| srvinfo             | Server information.                                           |
| enumdomains         | Enumerate all domains that are deployed in the network.       |
| querydominfo        | Provides domain, server, and user information of deployed domains. |
| netshareenumall     | Enumerates all available shares.                              |
| netsharegetinfo \<share\> | Provides information about a specific share.               |
| enumdomusers        | Enumerates all domain users.                                  |
| queryuser \<RID\>     | Provides information about a specific user.                  |
