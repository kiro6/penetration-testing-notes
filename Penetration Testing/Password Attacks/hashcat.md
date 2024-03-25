

# Hashcat

 - `-a` stands for attack mode  

| Mode | Description                 |
|-----:|-----------------------------|
| 0    | Straight                    |
| 1    | Combination                 |
| 3    | Brute-force and Mask attack |
| 6    | Hybrid Wordlist + Mask      |
| 7    | Hybrid Mask + Wordlist      |

```powershell
.\hashcat.exe -a 0 -m 0 0c352d5b2f45217c57bef9f8452ce376 .\wordlists\rockyou.txt

.\hashcat.exe -a 1 -m 0 19672a3f042ae1b592289f8333bf76c5 .\wordlists\w1.txt .\wordlists\w2.txt

.\hashcat.exe -a 3 -m 0 50a742905949102c961929823a2e8ca0 -1 02 'HASHCAT?l?l?l?l?l20?1?d'

.\hashcat.exe -a 6 -m 0 f7a4a94ff3a722bf500d60805e16b604 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt '?d?s'

.\hashcat.exe -a 7 -m 0 eac4fe196339e1b511278911cb77d453 -1 01 '20?1?d' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
```



- `-m` for hash type

| Option             | Description                                                                                                                                                     |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Optimized Kernels | This is the `-O` flag, which according to the documentation, means Enable optimized kernels (limits password length). The magical password length number is generally 32, with most wordlists won't even hit that number. This can take the estimated time from days to hours, so it is always recommended to run with `-O` first and then rerun after without the `-O` if your GPU is idle. |
| Workload          | This is the `-w` flag, which, according to the documentation, means Enable a specific workload profile. The default number is 2, but if you want to use your computer while Hashcat is running, set this to 1. If you plan on the computer only running Hashcat, this can be set to 3.                         |


## rules 

- [full list](https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions)


| Function | Description                                             | Input                | Output                                |
|----------|---------------------------------------------------------|----------------------|---------------------------------------|
| l        | Convert all letters to lowercase                       | InlaneFreight2020    | inlanefreight2020                    |
| u        | Convert all letters to uppercase                       | InlaneFreight2020    | INLANEFREIGHT2020                    |
| c / C    | Capitalize / lowercase first letter and invert the rest| inlaneFreight2020 / Inlanefreight2020 | Inlanefreight2020 / iNLANEFREIGHT2020 |
| t / TN   | Toggle case: whole word / at position N                | InlaneFreight2020    | iNLANEfREIGHT2020                    |
| d / q / zN / ZN | Duplicate word / all characters / first character / last character | InlaneFreight2020 | InlaneFreight2020InlaneFreight2020 / IInnllaanneeFFrreeiigghhtt22002200 / IInlaneFreight2020 / InlaneFreight20200 |
| { / }    | Rotate word left / right                               | InlaneFreight2020    | nlaneFreight2020I / 0InlaneFreight202 |
| ^X / $X  | Prepend / Append character X                           | InlaneFreight2020 (^! / $!) | !InlaneFreight2020 / InlaneFreight2020! |
| r        | Reverse                                                 | InlaneFreight2020    | 0202thgierFenalnI                    |

```
# The first letter word is capitalized with the c function. Then rule uses the substitute function s to replace o with 0, i with 1, e with 3 and a with @. At the end, the year 2019 is appended to it.
echo 'c so0 si1 se3 ss5 sa@ $2 $0 $1 $9' > rule.txt
echo 'password_ilfreight' > test.txt
hashcat -r rule.txt test.txt --stdout
```
