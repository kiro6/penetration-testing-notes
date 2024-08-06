

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
# list all current dir
ls -ahlR

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
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null 

# All Hidden Directories
find / -type d -name ".*" -ls 2>/dev/null

# Temporary Files
ls -l /tmp /var/tmp /dev/shm

# search the file system for words
grep -r -l 'HTB{' /

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


## Services & Internals Enumeration

```shell
# Network Interfaces
ip a

# Hosts
cat /etc/hosts

# User's Last Login
lastlog

#  is currently on the system with us
who <username>
finger <username>

# Logged In Users
w

# history
history

# Cron
ls -la /etc/cron.daily/

# Proc
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

# Installed Packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

# Sudo Version
sudo -V

# Binaries
ls -l /bin /usr/bin/ /usr/sbin/

# GTFObins exploitable binaries
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

# Trace System Calls
strace ping -c1 10.129.112.20


# Running Services by User
ps aux | grep root

```

search in the system 
```shell
# Configuration Files
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

## Credentials in Configuration Files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
for i in $(find / -name *.conf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
# Finding History Files
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null


## Databases
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

## Notes
find /home/* -type f -name "*.txt" -o ! -name "*.*"

## Scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

# find writable files or directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

## find crontabs
find /etc -type d -name '*cron*' -exec sh -c 'echo "Parent Directory: $1"; ls -lah "$1"' sh {} \;

## ssh keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"   ## private
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1        ## public

```

## network
```sh
# shell
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

# arp 
 arp -a
```
