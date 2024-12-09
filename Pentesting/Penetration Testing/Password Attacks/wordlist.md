## crunch

```bash
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>

# creates a wordlist consisting of words with a length of 4 to 8 characters, using the default character set
crunch 4 8 -o wordlist

# creates a wordlist start with ILFREIGHT201 then a number then 4 chars 
crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist
```

## cupp
can be used to create custom wordlists 
```
cupp -i 
```


## princeprocessor
password candidate generator using the PRINCE algorithm 

```bash 
princeprocessor  -o wordlist < words

princeprocessor --pw-min=10 --pw-max=25 -o wordlist.txt < words

```
 ## CeWL 

```bash
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>
```

## creds 
check default cred [install here](https://github.com/ihebski/DefaultCreds-cheat-sheet?tab=readme-ov-file)
```
$ creds search tomcat
+----------------------------------+------------+------------+
| Product                          |  username  |  password  |
+----------------------------------+------------+------------+
| apache tomcat host manager (web) |   admin    |   admin    |
| apache tomcat host manager (web) |   ADMIN    |   ADMIN    |
| apache tomcat host manager (web) |   admin    |  <blank>   |
| apache tomcat host manager (web) |   admin    |   j5Brn9   |
| apache tomcat host manager (web) |   admin    |   tomcat   |
| apache tomcat host manager (web) |   cxsdk    |   kdsxc    |
| apache tomcat host manager (web) | j2deployer | j2deployer |
| apache tomcat host manager (web) |  ovwebusr  | OvW*busr1  |
| apache tomcat host manager (web) |    QCC     |  QLogic66  |
| apache tomcat host manager (web) |   role1    |   role1    |
| apache tomcat host manager (web) |   role1    |   tomcat   |
| apache tomcat host manager (web) |    role    | changethis |
| apache tomcat host manager (web) |    root    |    root    |
| apache tomcat host manager (web) |   tomcat   | changethis |
| apache tomcat host manager (web) |   tomcat   |   s3cret   |
| apache tomcat host manager (web) |   tomcat   |   tomcat   |
| apache tomcat host manager (web) |   xampp    |   xampp    |
+----------------------------------+------------+------------+
```
