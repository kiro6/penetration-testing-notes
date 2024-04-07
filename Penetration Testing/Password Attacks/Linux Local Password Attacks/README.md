
**There are several sources that can provide us with credentials that we put in four categories:**

| Files              | History              | Memory               | Key-Rings                      |
|--------------------|----------------------|----------------------|--------------------------------|
| Configs            | Logs                 | Cache                | Browser stored credentials    |
| Databases          | Command-line History | In-memory Processing |                                |
| Notes              |                      |                      |                                |
| Scripts            |                      |                      |                                |
| Source codes       |                      |                      |                                |
| Cronjobs           |                      |                      |                                |
| SSH Keys           |                      |                      |                                |


## Files

```bash
## Configuration Files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

## Credentials in Configuration Files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

## Databases
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

## Notes
find /home/* -type f -name "*.txt" -o ! -name "*.*"

## Scripts
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

## ssh keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"   ## private
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1        ## public

```

### cronjobs
can be found in /etc/cron.daily, /etc/cron.hourly, /etc/cron.monthly, /etc/cron.weekly , /etc/cron.d/

```bash
cat /etc/crontab
ls -la /etc/cron.*/
```

## History

### Command-line History
- look in `.bash_history` and other files like `.bashrc` or `.bash_profile` can contain important information.

```bash
tail -n5 /home/*/.bash*
```

### Logs
we have 3 types of logs: Application Logs,Event Logs, Service Logs and System Logs


| Log File           | Description                                         |
|--------------------|-----------------------------------------------------|
| /var/log/messages  | Generic system activity logs.                       |
| /var/log/syslog    | Generic system activity logs.                       |
| /var/log/auth.log  | (Debian) All authentication related logs.          |
| /var/log/secure    | (RedHat/CentOS) All authentication related logs.   |
| /var/log/boot.log  | Booting information.                                |
| /var/log/dmesg     | Hardware and drivers related information and logs. |
| /var/log/kern.log  | Kernel related warnings, errors and logs.          |
| /var/log/faillog   | Failed login attempts.                              |
| /var/log/cron      | Information related to cron jobs.                   |
| /var/log/mail.log  | All mail server related logs.                       |
| /var/log/httpd     | All Apache related logs.                            |
| /var/log/mysqld.log| All MySQL server related logs.                      |


```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

## Memory and Cache
- [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin)

```bash
sudo python3 mimipenguin.py

sudo bash mimipenguin.sh 
```

