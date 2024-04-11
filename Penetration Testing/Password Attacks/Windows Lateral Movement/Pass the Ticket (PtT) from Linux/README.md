
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
