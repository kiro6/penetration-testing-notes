
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
