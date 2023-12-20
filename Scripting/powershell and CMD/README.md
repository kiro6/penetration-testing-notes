


# CMD 
## Basic Usage 
[quick reference](https://ss64.com/nt/)

- `rem ` (for comments)
- `help` or `"command" /?`
- `doskey /history`              
- `cls`
- `|`   (pipline)
- `>` and `>>`
- `<`
- `A & B`   (run A then B)
- `A && B`  (do B if A successed)
- `A || B`  (do B if A fails)
- `find`    (like grep in linux)
- `findstr` (like grep in linux)
- `where`   (`where PATH  file_want_to_find` or `where file` will search in path env )
- `sort`
- `fc`      (check diff between files)
- `comp`    (compare byte to byte)


## Working with Files and Directories 
- `cd` or `chdir `  (change dir)
- `dir`             (list dir) (`dir /A:H /A:D` for hidden files/dir)
- `tree`            (tree dir)
- `md` or `mkdir`   (create dir)
- `rd` or `rmdir`   (remove dir) (add `\S` for recusrive)
- `move`            (move file/dir or rename it)
- `xcopy`           (copy file/dir) (can be usefule for hacker it does not copy ACL attributes)
- `robocopy`        (copy file/dir)
- `copy`            (copy file)
- `more`            (read file)
- `type`            (read file)
- `del`             (delete file)
- `erase`           (delete file)      
- `ren`             (rename file)
- `fsutil`          (It allows users to perform tasks related to the file system)

## System Information
![InformationTypesChart_Updated_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/1d8ac151-10e9-48a8-898f-f658c58a23ab)

- `systeminfo`
- `hostname`
- `ver`
- `ipconfig`         (`/all` )
- `arp`              (`/a`)
- `whoami`           (`/priv`,`/group`)

### `net` command
```cmd 
net user         rem  allows us to display a list of all users on a host, information and to create or delete users
net localgroup
net group        rem  manage local or domain groups on a computer. must be run against a domain server such as the DC
net share        rem  display or configure shared resources on a computer. 
net view         rem  display a list of resources, such as computers or shared resources, that are available on the network. This includes domain resources, shares, printers, and more.
net start        rem  start a service and list all services in the system
net stop         rem  stop a service
net pause        rem  pause a service
net continue     rem  continue a service
```

### `WMIC` command

## Env Variables

## environment variables types

| Scope            | Permissions Required to Access                   | Registry Location                                               |
|-------------------|-------------------------------------------------|-----------------------------------------------------------------|
| System (Machine)  | Local Administrator or Domain Administrator      | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` |
| User              | Current Active User, Local Administrator, or Domain Administrator | `HKEY_CURRENT_USER\Environment`                                  |
| Process           | Current Child Process, Parent Process, or Current Active User | None (Stored in Process Memory)                                  |





- `%variable_name%`  (access variable)
- `set`              (Process scope)(set var will be removed when the cmd session end)
- `setx`             (user scope)(set a var will hat persists across sessions even after restarting the computer)
- `setx /M`          (system scope)
- `set/setx var_name=""`  (will delete the env variable)
EX: 
```cmd
C:\Users\alice> set SECRET_VAR=VerySecretInfo
C:\Users\alice> echo %SECRET%
VerySecretInfo

C:\Users\alice> setx SECRET_VAR "VerySecretInfo"

```

## Managing Services
- `sc` (Service Controller)
```cmd
C:\user> sc query type= service                      rem  Query All Active Services

C:\user> sc query <service name>                     rem  Querying for service

C:\user> sc start <service name>                     rem  Starting Services

C:\user> sc stop <service name>                      rem  Stopping Services

C:\user> sc config <service name> start= disabled    rem  Modifying Services
```

- `tasklist` (list of currently running processes)
```
C:\user> tasklist /svc
```
