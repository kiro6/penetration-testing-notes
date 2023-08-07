
## serialization pickle python 

### pickle store serialized object in binary format but it have textual representation for humans by `pickletools`

### structure 
1. `(` - Indicates the start of a compound data structure, such as a dictionary, list, or tuple.
    
2. `)` - Indicates the end of a compound data structure.
    
3.  `p` - Represents a reference to a persistent object (for dictionary values).
    
5. `s` - Indicates the end of the current tuple of arguments for a constructor.
    
6. `t` - Indicates the end of a tuple of arguments for a constructor.
    
7. `l` - symbol is used to represent a start list object.
    
8. `b` - Indicates the start of a binary data block. It is followed by the binary data.
    
9.  `d` - symbol is used to indicate the start of a dictionary (the opening parenthesis of a dictionary).
    
10. `a` - Indicates that the next object will be used as an argument to reconstruct an object. It is used for objects that are in a tuple of arguments, list, or dictionary.
    
11. `c` - Indicates that the next object will be used as an argument to reconstruct an object. It is used for callable objects, such as functions or classes.
    
12. `R` - Represents a reference to a previously serialized object. It is used when the same object appears multiple times in the pickled data.
    
13. `I` - Indicates that an integer follows. It is usually followed by the integer value.
    
14. `F` - Indicates that a floating-point number follows. It is usually followed by the floating-point value.
    
15. `S` - Indicates the start of a string. It is followed by a number indicating the length of the string and the actual string data.
    
16. `V` - Indicates the start of a Unicode string. It is followed by a number indicating the length of the string and the actual Unicode string data.
    
17. `X` - Indicates the start of a complex number. It is followed by the real and imaginary parts of the complex number.
    
18. `#` - Indicates a comment. It is followed by the comment text.
    
19. `.` - Indicates the end of the pickled data.
20. `N` - Represents `None`.



### example from `baby website rick challenge in HTB` 

```
(dp0
S'serum'
p1
ccopy_reg
_reconstructor
p2
(c__main__
anti_pickle_serum
p3
c__builtin__
object
p4
Ntp5
Rp6
s.
```

### this object produced from code like this 
```python
import pickle
import pickletools
import base64

class anti_pickle_serum(object):
    def __init__(self) -> None:
        pass

obj = anti_pickle_serum()
raw_pickle = pickle.dumps({"serum" : obj}, protocol=0)

optimed_pickle = pickletools.optimize(raw_pickle)
pickletools.dis(optimed_pickle)

ser_obj = base64.b64encode(raw_pickle)

print(ser_obj)
```

### lets explain 

-  `(dp0`: Indicates the start of a dictionary (the opening parenthesis `(` of a dictionary).
-  `S'serum'`: Represents the key `'serum'`. In this context, it is just a string.
-  `p1`: Indicates that the next object (in this case, `ccopy_reg`) will be used as the value associated with the key `'serum'`. However, in this serialized data, the next object is not a value for the key `'serum'`; it is rather part of the object reconstruction process.
-  `ccopy_reg`: Represents the `copy_reg` module used for object reconstruction.- . `_reconstructor`: Represents the specific method from the `copy_reg` module used for reconstruction.

```
1. `copy_reg`: This is a module in the Python `pickle` module, which provides functions to register custom object constructors for pickling and unpickling. It allows you to define custom pickling/unpickling behavior for classes that are not natively supported by the `pickle` module.
    
2. `_reconstructor`: This is a specific function from the `copy_reg` module, used for object reconstruction during unpickling. It allows you to define a function that reconstructs an object based on the pickled data.
    

When you want to pickle an object that is not natively supported by the `pickle` module (e.g., a custom class), Python will raise a `PicklingError`. To handle such custom objects, you can use the `copy_reg` module to register the constructor function (the `_reconstructor`) for the custom class, which the `pickle` module will use during the unpickling process.
```

- `p2`: Indicates that the next object (in this case, `(c__main__anti_pickle_serum`) will be used as an argument to the `_reconstructor` function.
- `(c__main__anti_pickle_serum`: Represents the class `anti_pickle_serum` defined in the `__main__` module. It will be used to reconstruct the object.
- `p3`: Indicates that the next object (in this case, `c__builtin__object`) will be used as an argument to the constructor of the class `anti_pickle_serum`.
- `c__builtin__object`: Represents the base class (`object`) used for object reconstruction.
- `p4`: Indicates that the next object (`N`) will be used as another argument to the constructor of the class `anti_pickle_serum`.
- `N`: Represents `None`. In this case, it is an argument to the constructor of the class `anti_pickle_serum`.
- `tp5`: Indicates the end of the tuple of arguments for the constructor.
- `Rp6`: Represents a reference to a previously serialized object (in this case, `None` with ID 0). It is used when the same object appears multiple times in the pickled data.
- `s.`: Indicates the end of the dictionary (key-value pairs) and the end of the serialized object.

### how to use pickle-tools 
```python
import pickle
import pickletools
from base64 import b64decode


class anti_pickle_serum(object):
    def __init__(self) -> None:
        pass


data = b'KGRwMApTJ3NlcnVtJwpwMQpjY29weV9yZWcKX3JlY29uc3RydWN0b3IKcDIKKGNfX21haW5fXwphbnRpX3BpY2tsZV9zZXJ1bQpwMwpjX19idWlsdGluX18Kb2JqZWN0CnA0Ck50cDUKUnA2CnMu' #this is the serialized object but base64 encoded 

decoded_data = b64decode(data)

opt_data = pickletools.optimize(decoded_data)
pickletools.dis(opt_data)

obj = pickle.loads(opt_data)
print(obj)
```

- output
```bash
$ python ser.py   
    0: (    MARK
    1: d        DICT       (MARK at 0)
    2: S    STRING     'serum'
   11: c    GLOBAL     'copy_reg _reconstructor'
   36: (    MARK
   37: c        GLOBAL     '__main__ anti_pickle_serum'
   65: c        GLOBAL     '__builtin__ object'
   85: N        NONE
   86: t        TUPLE      (MARK at 36)
   87: R    REDUCE
   88: s    SETITEM
   89: .    STOP
highest protocol among opcodes = 0
{'serum': <__main__.anti_pickle_serum object at 0x7f67ab33b9d0>}
```

### another example 

```
(dp1
S'text'
p2
S'string'
p3
sS'none'
p4
N
sS'boolean'
p5
I01
sS'number'
p6
F3.4399999999999999
sS'int_list'
p7
(lp8
I1
aI2
aI3
as.
```

- this is translated to something like this in json
```json
{"int_list": [1, 2, 3], "text": "string", "number": 3.44, "boolean": true, "none": null}
```
