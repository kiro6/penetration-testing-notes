# Cotnent 
- [Handling ASCII](#handling-ascii)
- [Handling Hex](#handling-hex)
- [Handling Base64](#handling-base64)
- [PyCryptodome](#pycryptodome)
    - [Messages Into Numbers](#messages-into-numbers)
- [pwntools](#pwntools)
    - [XOR](#xor)


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
```bash
$ python3 py.py
crypto{ASCII_pr1nt4bl3}

[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
```

## Handling Hex 
 In Python, the bytes.fromhex() function can be used to convert hex to bytes. The .hex() instance method can be called on byte strings to get the hex representation.
```python
hex = '63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d'

flag = bytes.fromhex(hex)

print(flag)
print()
print(bytes.hex(flag))
```
output
```bash
$ python3 py.py                                                                                                                                                1 ↵
b'crypto{You_will_be_working_with_hex_strings_a_lot}'

63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d
```

## Handling Base64
```python
from base64 import *

b64 = 'Y3J5cHRve0Jhc2VfNjRfRW5jb2RpbmdfaXNfV2ViX1NhZmV9'

s = b64decode(b64)
print(s)
print()
print(b64encode(s))
```
output
```bash
b'crypto{Base_64_Encoding_is_Web_Safe}'

b'Y3J5cHRve0Jhc2VfNjRfRW5jb2RpbmdfaXNfV2ViX1NhZmV9'
```

## PyCryptodome
### Messages Into Numbers
messages into numbers so that mathematical operations can be applied
```python
from Crypto.Util.number import * 

string = 'AnyRandomText'
bytes = bytes(string , 'utf-8')
long= bytes_to_long(bytes)
print(long)
bytes  = long_to_bytes(long)
print(bytes)
```
output
```python
$ python3 py.py
                                                                                                                                1 ↵
5184020583563043647088157358196

b'AnyRandomText'
```
## pwntools
### XOR 
```python
import pwn 

# xor every byte of 'Random' with 13
print(pwn.xor(b'Random' , 13))
```
output
```
b'_lcib`'
```
