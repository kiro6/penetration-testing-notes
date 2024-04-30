
# Enumeration
- [LinEnum tool](https://github.com/rebootuser/LinEnum)
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
