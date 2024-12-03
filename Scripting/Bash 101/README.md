# content 
- [Special Variables](#special-variables)
- [Operators](#operators)
  - [String Operators](#string-operators)
  - [Integer Operators](#integer-operators)
  - [File Operators](#file-operators)
  - [Logical Operators](#logical-operators)
- [Braces](#braces) 
- [Manipulation](#manipulation)
  - [Substitution](#substitution)  
  - [Slicing](#slicing)
- [Debugging](#debugging)
  - [Return Values](#return-values)
  - [xtrace](#xtrace--x)
- [Condtions](#condtions)
- [loops](#loops)
- [read files](#read-files)

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


# Braces

## Curly braces { }
1. Grouping Commands
```bash
#!/bin/bash
{
    echo "Command 1"
    echo "Command 2"
} > output.txt

```
2. Creating a Sequence:
```bash
#!/bin/bash
echo Number_{1..5}
```
3. parameter/array expansion
```bash
#!/bin/bash
string="Hello"
echo "${string} World!"


my_array=("apple" "banana" "cherry")
echo  ${my_array[1]}

```
## Double square brackets
1. conditional expressions
```bash
if [[ $string1 == $string2 ]]; then
    echo "Strings are equal."
else
    echo "Strings are not equal."
fi
```
2. access array index
```bash
my_array=("apple" "banana" "cherry")
echo  ${my_array[1]}
```

## parentheses 
1. Command Substitution
```
#!/bin/bash

result=$(echo "Hello, World!")
echo $result

```
2. math
```
$ echo $((1+1))
2

$ num=5 ; ((num++)) ; echo $num
6
```

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


# Condtions

always use `[[]]` not `[]` which is enhanced version 
```bash
if [[ $variable1 -eq $variable2 ]]; then
    echo "Variables are equal."
elif [[ $variable1 -eq $variable3 ]]; then
    echo "Variables are equal."
else
    echo "Variables are not equal."
fi

```
`(())` used for Arithmetic Expressions
```bash
if (( num1 > num2 )); then
    echo "$num1 is greater than $num2."
else
    echo "$num1 is not greater than $num2."
fi

```
# loops 
```bash

# for
for i in {1..5}
do
    echo "Iteration $i"
done

# while
count=1
while [[ $count -le 5 ]]
do
    echo "Iteration $count"
    ((count++))
done

# until
count=1
until [[ $count -gt 5 ]]
do
    echo "Iteration $count"
    ((count++))
done


```
# Read files
```bash

## this trim the white spaces
filepath="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
subs=()

if [[ -e $filepath ]]; then
    while read -r line ; do
        subs+=("$line")
    done < "$filepath"
fi;

## if we want to not trim the lines 
filepath="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
subs=()

if [[ -e $filepath ]]; then
    while IFS= read -r line ; do
        subs+=("$line")
    done < "$filepath"
fi; 


```
