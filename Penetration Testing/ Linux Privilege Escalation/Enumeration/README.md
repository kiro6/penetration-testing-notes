

# Enumeration
- OS Version
- Kernel Version
- Running Services
- Installed Packages and Versions
- Logged in Users
- User Home Directories (Are other user's home directories accessible?)
- Sudo Privileges
- Configuration Files
- Readable Shadow File
- Password Hashes in /etc/passwd
- Cron Jobs
- Unmounted File Systems and Additional Drives (`lsblk`)
- SETUID and SETGID Permissions
- Writeable Directories
```shell
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```
- Writeable Files
```shell
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

# Tools
- [LinEnum tool](https://github.com/rebootuser/LinEnum)
- [linPEAS tool](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)

## Environment Enumeration

```shell
# operating system and version
cat /etc/os-release

# Kernel version
uname -a

# PATH variable for a target user is misconfigured we may be able to leverage it to escalate privileges.
echo $PATH

# find something sensitive in there such as a password
env

# CPU type/version
lscpu

# What login shells exist
cat /etc/shells

# enumerate information about block devices on the system (hard disks, USB drives, optical drives, etc.)
lsblk

# Mounted File Systems
df -h

# find any types of credentials in fstab for mounted drives by grepping for common words such as password, username, credential
cat /etc/fstab

# Unmounted File Systems
cat /etc/fstab | grep -v "#" | column -t

# can be used to find information about any printers attached to the system. If there are active or queued print jobs can we gain access to some sort of sensitive information?
lpstat 

# what other networks are available via which interface
route
netstat -rn

#  if the host is configured to use internal DNS we may be able to use this as a starting point to query the Active Directory environment.
cat /etc/resolv.conf

# check the arp table to see what other hosts the target has been communicating with.
arp -a

# All Hidden Files
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student

# All Hidden Directories
find / -type d -name ".*" -ls 2>/dev/null

# Temporary Files
ls -l /tmp /var/tmp /dev/shm


```

### Existing Users
1. Username
2. Password
3. User ID (UID)
4. Group ID (GID)
5. User ID info
6. Home directory
7. Shell

```shell
# users
cat /etc/passwd | cut -f1 -d:

# shell
grep "*sh$" /etc/passwd

# Existing Groups
cat /etc/group

# command to list members of any interesting groups.
getent group sudo
```

### Defenses in place
- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)



