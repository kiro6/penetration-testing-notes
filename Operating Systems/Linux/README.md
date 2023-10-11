# Content
- [File System Hierarchy](#file-system-hierarchy)
- [Basic commands](#basic-commands)
  - [System Information](#system-information)
  - [Working with Files and Directories](#working-with-files-and-directories)
    - [grep syntax ](#grep-syntax )
    - [cut syntax](#cut-syntax)
    - [tr syntax](#tr-syntax)
    - [column syntax](#column-syntax)
    - [awk syntax](#awk-syntax)
    - [sed syntax](#sed-syntax)
- [Find Files and Directories](#find-files-and-directories)
  - [find syntax](#find-syntax) 

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

### awk syntax 
```bash
awk 'pattern { action }' input-file


## Print specific columns from a file:
awk '{ print $1, $3 }' input.txt

## Filter lines based on a condition:
awk '$3 > 50' input.txt

## Perform calculations:
awk '{ total += $2 } END { print "Total:", total }' input.txt

## Using field separators:
awk -F':' '{ print $1, $3 }' /etc/passwd


## Using predefined variables:
awk '/pattern/ { print "Line number:", NR, "Content:", $0 }' input.txt
```

**awk predefined variables:**

| Variable      | Description                                                                         | Example Usage                                | Usage                                   |
|-------------- |-------------------------------------------------------------------------------------|----------------------------------------------|--------------------------------------------|
| `$0`          | Represents the entire input record (the current line).                              | `awk '/apple/ { print $0 }' input.txt`        | Print lines containing the word "apple."  |
| `$1`, `$2`,...| Represent the fields in the input record. Fields are separated by a field separator (usually whitespace by default). | `awk '{ print $1, $3 }' input.txt`        | Print the first and third fields.         |
| `NF`          | Stands for "Number of Fields." It contains the number of fields in the current input record. | `awk 'NF == 5 { print $0 }' input.txt` | Print lines with exactly 5 fields.        |
| `$NF`         | Represents the value of the last field in the current input record.                | `awk '{ print $NF }' input.txt`        | Print the last field of each line.        |
| `NR`          | Stands for "Number of Records." It contains the current record number (line number). | `awk '/banana/ { print NR, $0 }' input.txt` | Print line numbers for lines containing the word "banana." |
| `FS`          | Stands for "Field Separator." It specifies the character or regular expression used to separate fields. | `awk -F ';' '{ print $1, $2 }' data.csv` | Use a semicolon as the field separator to process a CSV file. |
| `OFS`         | Stands for "Output Field Separator." It specifies the character used to separate fields in the output. | `awk 'BEGIN { OFS="\t" } { print $1, $2 }' input.txt` | Change the output field separator to a tab. |
| `RS`          | Stands for "Record Separator." It specifies the character or regular expression used to separate records (lines). | `awk 'BEGIN { RS="\n\n" } { print $0 }' input.txt` | Use a double newline to separate records. |
| `ORS`         | Stands for "Output Record Separator." It specifies the character used to separate records in the output. | `awk 'BEGIN { ORS="\n---\n" } { print $0 }' input.txt` | Change the output record separator to a newline followed by a line of dashes. |
| `FILENAME`    | Contains the name of the current input file being processed.                        | `awk '{ print FILENAME, $0 }' file1.txt file2.txt` | Print the filename for each line in multiple files. |
| `FNR`         | Stands for "File Number of Records." It contains the current record number within the current input file. | `awk '{ print FNR, $0 }' file1.txt file2.txt` | Print line numbers within each file. |
| `ARGV`, `ARGC`| Used to access command-line arguments and their count.                            | `awk 'BEGIN { for (i = 0; i < ARGC; i++) print ARGV[i] }' file1.txt file2.txt` | Print all command-line arguments. |
| `ENVIRON`    | An associative array that provides access to environment variables.                  | `awk 'BEGIN { print ENVIRON["PATH"] }'` | Print the value of the "PATH" environment variable. |
| `IGNORECASE` | If set to a non-zero value, it makes string matching case-insensitive.               | `awk 'BEGIN { IGNORECASE=1 } /apple/ { print $0 }' input.txt` | Perform a case-insensitive search for the word "apple." |
| `RS`          | The value of the input record separator, usually a newline.                           | `awk 'BEGIN { RS=";" } { print $0 }' input.txt` | Use a semicolon as the input record separator. |


### sed syntax 

```bash
##Substitution (s): Replace one pattern with another.
sed 's/pattern/replacement/' inputfile

##Print (p): Print lines that match a specific pattern.
sed -n '/pattern/p' inputfile

##Delete (d): Delete lines that match a specific pattern.
sed '/pattern/d' inputfile

##Append (a): Add text after a specific line.
sed '/pattern/a\New text' inputfile

##Insert (i): Add text before a specific line.
sed '/pattern/i\New text' inputfile

##Replace (c): Replace specific lines with new text.
sed '/pattern/c\New text' inputfile

##Address Range: You can specify a range of lines to apply a command. For example, to perform a substitution from line 3 to 5:
sed '3,5s/pattern/replacement/' inputfile

##Global (g): Apply a command globally, not just on the first occurrence on each line.
sed 's/pattern/replacement/g' inputfile

##In-place Editing (-i): Modify the original file in place.
sed -i 's/pattern/replacement/' inputfile
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
