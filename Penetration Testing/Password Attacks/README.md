# John The Ripper

**Cracking with John**
```
$ john --format=<hash_type> <hash or hash_file>
$ john --format=<hash_type> --wordlist=<wordlist_file> --rules <hash_file>
$ john --incremental <hash_file>
```

**Cracking Files with John**
```
$ <tool> <file_to_crack> > file.hash
$ pdf2john server_doc.pdf > server_doc.hash
$ john server_doc.hash
                # OR
$ john --wordlist=<wordlist.txt> server_doc.hash 
```

| Tool                 | Description                                    |
|----------------------|------------------------------------------------|
| pdf2john             | Converts PDF documents for John                |
| ssh2john             | Converts SSH private keys for John             |
| mscash2john          | Converts MS Cash hashes for John               |
| keychain2john        | Converts OS X keychain files for John          |
| rar2john             | Converts RAR archives for John                 |
| pfx2john             | Converts PKCS#12 files for John               |
| truecrypt_volume2john| Converts TrueCrypt volumes for John            |
| keepass2john         | Converts KeePass databases for John            |
| vncpcap2john         | Converts VNC PCAP files for John               |
| putty2john           | Converts PuTTY private keys for John           |
| zip2john             | Converts ZIP archives for John                 |
| hccap2john           | Converts WPA/WPA2 handshake captures for John  |
| office2john          | Converts MS Office documents for John          |
| wpa2john             | Converts WPA/WPA2 handshakes for John          |


# CrackMapExec


