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
