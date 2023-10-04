# Cotnent 
- handling ascii


## Handling ASCII
In Python, the chr() function can be used to convert an ASCII ordinal number to a character (the ord() function does the opposite).
```python
ASCII = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
string= ''
for c in ASCII : 
    string = string + chr(c) 

print(string + '\n') 

list = []
for s in string :
    list.append(ord(s)) 

print(list)
```
output 
```
$ python3 py.py
crypto{ASCII_pr1nt4bl3}

[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
```
