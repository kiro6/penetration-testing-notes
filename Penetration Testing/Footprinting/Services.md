# Content 
- [FTP](#ftp)

## FTP
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
