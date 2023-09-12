# content 
- [Special Variables](#special-variables)
- [Operators](#operators)
  - [String Operators](#string-operators)
  - [Integer Operators](#integer-operators)
  - [File Operators](#file-operators)
  - [Logical Operators](#logical-operators)
- [Manipulation](#manipulation)
  - [Substitution](#substitution)  
  - [Slicing](#slicing)
- [Debugging](#debugging)
  - [Return Values](#return-values)
  - [xtrace](#xtrace--x)

# Special Variables

| Variable | Description                                                                                         |
|----------|-----------------------------------------------------------------------------------------------------|
| $0       | This variable stores the name of the currently running script or shell.                           |
| $1, $2, $3, ... | These variables hold the positional parameters passed to the script or function. $1 represents the first argument, $2 represents the second argument, and so on. |
| $@       | This variable represents all the positional parameters as a list of separate arguments.           |
| $#       | This variable stores the number of arguments passed to the script or function.                    |
| $?       | After executing a command, this variable stores the exit status of the last executed command.     |
| $$       | This variable holds the process ID (PID) of the currently running shell or script.                 |
| $!       | After running a background command or job, this variable holds the PID of the last background process. |
| $*       | Similar to $@, this variable represents all positional parameters as a single string, with arguments separated by the first character in the $IFS (Internal Field Separator) variable. |

## Notes 
- this char `#` before any variable will output the length.
- this expression  `${var} == *${value}*` checks if the variable named **var** contains the contents of the variable named **value**.



# Operators

## String Operators

| Operator | Description                               |
|----------|-------------------------------------------|
| ==       | is equal to                               |
| !=       | is not equal to                           |
| <        | is less than in ASCII alphabetical order |
| >        | is greater than in ASCII alphabetical order |
| -z       | if the string is empty (null)            |
| -n       | if the string is not null                |

## Integer Operators

| Operator | Description                   |
|----------|-------------------------------|
| -eq      | is equal to                   |
| -ne      | is not equal to               |
| -lt      | is less than                  |
| -le      | is less than or equal to      |
| -gt      | is greater than               |
| -ge      | is greater than or equal to   |


## File Operators

| Operator | Description                                   |
|----------|-----------------------------------------------|
| -e       | if the file exists                            |
| -f       | tests if it is a file                        |
| -d       | tests if it is a directory                   |
| -L       | tests if it is a symbolic link               |
| -N       | checks if the file was modified after it was last read |
| -O       | if the current user owns the file            |
| -G       | if the file’s group id matches the current user’s |
| -s       | tests if the file has a size greater than 0  |
| -r       | tests if the file has read permission        |
| -w       | tests if the file has write permission       |
| -x       | tests if the file has execute permission     |

## Logical Operators

| Operator | Description          |
|----------|----------------------|
| !        | logical negation NOT |
| &&       | logical AND          |
| ||       | logical OR           |

# Manipulation 

## Substitution
```bash
name="John"
echo "${name/J/j}"    #=> "john"
```
## Slicing
```bash
name="John"
echo "${name:0:2}"    #=> "Jo" (slicing)
echo "${name::2}"     #=> "Jo" (slicing)
echo "${name::-1}"    #=> "Joh" (slicing)
echo "${name:(-1)}"   #=> "n" (slicing from right)
echo "${name:(-2):1}" #=> "h" (slicing from right)
```

# Debugging

## Return Values
| Return Code | Description                                        |
|-------------|----------------------------------------------------|
| 1           | General errors                                     |
| 2           | Misuse of shell builtins                          |
| 126         | Command invoked cannot execute                    |
| 127         | Command not found                                 |
| 128         | Invalid argument to exit                          |
| 128+n       | Fatal error signal "n"                            |
| 130         | Script terminated by Control-C                     |
| 255*        | Exit status out of range (greater than 255)       |

## xtrace (-x)
```bash
bash -x  bash.sh                                                                                                                                                                         
+ name
+ echo asas
asas
+ not_a_function
bash.sh: line 8: not_a_function: command not found
```
