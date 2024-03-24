

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
```



- `-m` for hash type

| Option             | Description                                                                                                                                                     |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Optimized Kernels | This is the `-O` flag, which according to the documentation, means Enable optimized kernels (limits password length). The magical password length number is generally 32, with most wordlists won't even hit that number. This can take the estimated time from days to hours, so it is always recommended to run with `-O` first and then rerun after without the `-O` if your GPU is idle. |
| Workload          | This is the `-w` flag, which, according to the documentation, means Enable a specific workload profile. The default number is 2, but if you want to use your computer while Hashcat is running, set this to 1. If you plan on the computer only running Hashcat, this can be set to 3.                         |
