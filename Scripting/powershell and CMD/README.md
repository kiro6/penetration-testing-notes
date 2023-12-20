


# CMD 
## Basic Usage 
[quick reference](https://ss64.com/nt/)


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
- `net user`         (allows us to display a list of all users on a host, information and to create or delete users.)
- `net localgroup`
- `net group`        (must be run against a domain server such as the DC)
- `net share`    (allows us to display info about shared resources on the host and to create new shared resources as well.)
- `net view` (will display to us any shared resources the host you are issuing the command against knows of. This includes domain resources, shares, printers, and more.)
