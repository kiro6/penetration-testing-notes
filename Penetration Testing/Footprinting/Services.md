# Content 
- [FTP](#ftp)
- [SMB](#smb)
- [NFS](#nfs)
- [DNS](#dns)
- [SMTP](#smtp)
- [IMAP / POP3](#imap--pop3)

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
- Impacket - Samrdump.py
```bash
# used to enumrate RIDs
/usr/share/doc/python3-impacket/examples/samrdump.py 10.129.14.128
```
- smbmap
```bash
smbmap -H 10.129.202.5 -s sambashare
```
- metasploit
```bash
# bruteforce login
msf > use auxiliary/scanner/smb/smb_login
```
### Service Interaction
- smbclient
```
smbclient -N -L //10.129.14.128
```

- smb commands

| Command        | Description                                                  |
|----------------|--------------------------------------------------------------|
| `?`            | Displays a list of available commands or provides help.       |
| `allinfo`      | Displays detailed information about a file or directory.     |
| `cd`           | Changes the current working directory on the remote server.   |
| `get`          | Downloads a file from the remote server.                     |
| `put`          | Uploads a file to the remote server.                         |
| `ls`           | Lists the contents of the current directory on the server.   |
| `mkdir`        | Creates a new directory on the remote server.                |
| `pwd`          | Prints the current working directory on the server.          |
| `quit` (`q`)   | Exits the `smbclient` session.                               |



- rpcclient
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

## NFS
- Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. 
- NFS is used between Linux and Unix systems. This means that NFS clients cannot communicate directly with SMB servers.

### port used  
- Port 2049 TCP or UDP: NFS 
- Port 111 TCP or UDP : for SUN Remote Procedure Call which is used as portmapper .and nfs rely on it for auth
### Dangerous Settings

| Option          | Description                                                                                      |
|-----------------|--------------------------------------------------------------------------------------------------|
| rw              | Read and write permissions.                                                                      |
| insecure        | Ports above 1024 will be used.                                                                   |
| nohide          | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| no_root_squash  | All files created by root are kept with the UID/GID 0.                                           |

### Footprinting the Service
- nmap
```
sudo nmap 10.129.14.128 -p111,2049 -sV -sC --script nfs*
```
### Service Interaction
```bash
$ showmount -e 10.129.14.128

$ mkdir target-NFS
$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
$ cd target-NFS
$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share




$ cd ..
$ sudo umount ./target-NFS
```
## DNS

### Dangerous Settings

| Option            | Description                                                     |
|-------------------|-----------------------------------------------------------------|
| allow-query       | Defines which hosts are allowed to send requests to the DNS server. |
| allow-recursion   | Defines which hosts are allowed to send recursive requests to the DNS server. |
| allow-transfer    | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| zone-statistics   | Collects statistical data of zones.                             |


### Service Interaction
- dig
- dnsenum
```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

## SMTP

### port used
- Port 25/tcp  old but gold smtp
- Port 587/tcp modern smtp support tls
- Port 465/tcp deprcated but still widly used for smtp and support tls
- Port 2525/tcp not an official SMTP port but still popularly used 

### Dangerous Settings
- open relay
```
mynetworks = 0.0.0.0/0
```
### Footprinting the Service
- nmap 
```
sudo nmap 10.129.14.128 -sC -sV -p25 --script smtp-open-relay
```

- enum usernames
```
smtp-user-enum -M VRFY -U username   -t 10.129.247.222  -p 25 -w 60
```

### Service Interaction
- Telnet
```
telnet 10.129.14.128 25
```

- smtp commands

| Command     | Description                                            |
|-------------|--------------------------------------------------------|
| HELO        | Identifies the sender's SMTP client to the server.     |
| EHLO        | Extended HELO command providing additional capabilities.|
| MAIL FROM:  | Specifies the email address of the sender.             |
| RCPT TO:    | Specifies the email address of the recipient.          |
| DATA        | Indicates the start of the email message data.         |
| QUIT        | Terminates the SMTP session and closes the connection. |
| AUTH        | Initiates authentication process with the server.      |
| NOOP        | No-operation command, used to keep the connection alive.|
| RSET        | Resets the current session, discarding previous commands.|
| VRFY        | Verifies the existence of a specific email address.    |
| HELP        | Requests help information from the server.             |
| STARTTLS    | Initiates a secure connection using TLS encryption.    |

## IMAP / POP3
