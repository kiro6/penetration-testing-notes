# Content
- [File System Hierarchy](#file-system-hierarchy)

# File System Hierarchy


![NEW_filesystem](https://github.com/kiro6/penetration-testing-notes/assets/57776872/fc0ea4cf-f620-4818-bfbe-0ca39823c49a)


| Path | Description  |
|----------|----------|
| / | The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root. |
| /bin | Contains essential command binaries. |
| /boot | Consists of the static bootloader, kernel executable, and files required to boot the Linux OS. |
| /dev | Contains device files to facilitate access to every hardware device attached to the system. |
| /etc | Local system configuration files. Configuration files for installed applications may be saved here as well. |
| /home | Each user on the system has a subdirectory here for storage. |
| /lib | Shared library files that are required for system boot. |
| /media | External removable media devices such as USB drives are mounted here. |
| /mnt | Temporary mount point for regular filesystems. |
| /opt | Optional files such as third-party tools can be saved here. |
| /root | The home directory for the root user. |
| /sbin | This directory contains executables used for system administration (binary system files). |
| /tmp | The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning. |
| /usr | Contains executables, libraries, man files, etc. |
| /var | This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more. |

# Basic commands 

## System Information

| Command   | Description                                                           |
|-----------|-----------------------------------------------------------------------|
| whoami    | Displays current username.                                            |
| id        | Returns user's identity.                                              |
| hostname  | Sets or prints the name of the current host system.                  |
| uname     | Prints basic information about the operating system name and system hardware. |
| pwd       | Returns working directory name.                                       |
| ifconfig  | The ifconfig utility is used to assign or view an address to a network interface and/or configure network interface parameters. |
| ip        | Ip is a utility to show or manipulate routing, network devices, interfaces, and tunnels. |
| netstat   | Shows network status.                                                 |
| ss        | Another utility to investigate sockets.                                |
| ps        | Shows process status.                                                 |
| who       | Displays who is logged in.                                            |
| env       | Prints environment or sets and executes a command.                     |
| lsblk     | Lists block devices.                                                  |
| lsusb     | Lists USB devices.                                                    |
| lsof      | Lists opened files.                                                   |
| lspci     | Lists PCI devices.                                                    |


## Working with Files and Directories

| Command  | Description                              |
|----------|------------------------------------------|
| `ls`     | Lists directory contents.                 |
| `cd`     | Changes the directory.                    |
| `clear`  | Clears the terminal.                      |
| `touch`  | Creates an empty file.                   |
| `mkdir`  | Creates a directory.                      |
| `tree`   | Lists the contents of a directory recursively. |
| `mv`     | Move or rename files or directories.      |
| `cp`     | Copy files or directories.                |
| `more`    | Pager that is used to read STDOUT or files.                       |
| `less`    | An alternative to `more` with more features.                      |
| `head`    | Prints the first ten lines of STDOUT or a file.                   |
| `tail`    | Prints the last ten lines of STDOUT or a file.                    |
| `sort`    | Sorts the contents of STDOUT or a file.                           |
| `grep`    | Searches for specific results that contain given patterns.        |
| `cut`     | Removes sections from each line of files.                         |
| `tr`      | Replaces certain characters.                                      |
| `column`  | Command-line based utility that formats its input into multiple columns. |
| `awk`     | Pattern scanning and processing language.                         |
| `sed`     | A stream editor for filtering and transforming text.              |
| `wc`      | Prints newline, word, and byte counts for a given input.          |

### grep syntax 
```bash
#Search for a Word in a File:
grep "search_word" filename


#Case-Insensitive Search:
grep -i "search_word" filename


#Recursive Search in Directory:
grep -r "search_word" directory/


#Count Matching Lines:
grep -c "search_word" filename


#Search for Inverted Matches:
grep -v "exclude_word" filename


#Display Line Numbers:
grep -n "search_word" filename


#Search for a Regular Expression:
grep -E "pattern" filename


#Search Multiple Files:
grep "search_word" file1 file2 file3


#Piping Input:
cat file.txt | grep "search_word"


#Searching with Wildcards:
grep "pattern.*" filename
```
### cut syntax 
```bash
#Extract specific fields from a CSV file:
cut -d',' -f2,4 input.csv

#Extract characters from a text file:
cut -c1-5,10-20 textfile.txt

#Extract all fields except the specified ones:
cut -f2-4 --complement data.txt

#Extract fields from standard input:
echo "1,John,Smith" | cut -d',' -f2

#Extract characters from a variable (bash variable expansion):
variable="Hello,World"
echo "$variable" | cut -c1-5
```

### tr syntax 
```bash
#Translate characters from one set to another:
echo "Hello" | tr 'aeiou' 'AEIOU'
# Output: HEllo

#Delete specific characters:
echo "Remove spaces" | tr -d ' '
# Output: Removespaces

#Squeeze repeated characters:
echo "Helloooo" | tr -s 'o'
# Output: Helo

```

### column syntax 
```bash
#Format data into a table with default separator (whitespace):
column -t file.txt

#Format data into a table with a custom separator (e.g., comma):
column -s',' -t file.csv

#Specify a custom output separator (e.g., a pipe "|"):
column -s',' -o'|' -t file.csv

```

## Find Files and Directories
| Command   | Description                                                           |
|-----------|-----------------------------------------------------------------------|
| which     | locate a command binary                                            |
| locate    | list files in databases that match a pattern.                      |
| find  | search for files in a directory hierarchy                 |

### find syntax
```bash
#find <location> <options>
find / -type f -name *.conf -user root -size -28k -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null
```
