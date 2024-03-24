hashes are stored in certain formats. 
- hash:salt
- $id$salt$hash

**you can identify through id**
```bash
$1$  : MD5
$2a$ : Blowfish
$2y$ : Blowfish, with correct handling of 8 bit characters
$5$  : SHA256
$6$  : SHA512
```
