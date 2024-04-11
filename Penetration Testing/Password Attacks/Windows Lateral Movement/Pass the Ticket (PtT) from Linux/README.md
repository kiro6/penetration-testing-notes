
## Identifying Linux and Active Directory Integration

### realm - Check If Linux Machine is Domain Joined
```
realm list
```

### command line - Check if Linux Machine is Domain Joined
we can also look for other tools used to integrate Linux with Active Directory such as `sssd` or `winbind`. 
```powershell
# You might get the output similar to below if the system is integrated with AD using SSSD service.
$ ps -ef | grep -i "winbind\|sssd"
root     29912     1  0  2017 ?        00:19:09 /usr/sbin/sssd -f -D
root        2141    2140  0 Sep29 ?        00:00:08 /usr/libexec/sssd/sssd_be --domain inlanefreight.htb --uid 0 --gid 0 --logger=files

# You might get the output similar to below if the system is integrated with AD using winbind service.
$ ps -ef | grep -i "winbind\|sssd"
root       676 21055  0  2017 ?        00:00:22 winbindd

# Ceck whether the Linux server is integrated with AD using id Command
$ id daygeek
uid=1918901106(daygeek) gid=1918900513(domain users) groups=1918900513(domain users)

# check whether the Linux server is integrated with AD using nsswitch.conf file
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

