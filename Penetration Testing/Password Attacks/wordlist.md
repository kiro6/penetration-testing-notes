# crunch

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
