# Content 
- [ASCII](#ascii)
- [HEX](#hex)
- [Base64](#base64)

## ASCII 
ASCII is a 7-bit encoding standard which allows the representation of text using the integers 0-127.
```
$ man ascii  

  Oct   Dec   Hex   Char                        Oct   Dec   Hex   Char
────────────────────────────────────────────────────────────────────────
  000   0     00    NUL '\0' (null character)   100   64    40    @
  001   1     01    SOH (start of heading)      101   65    41    A
  002   2     02    STX (start of text)         102   66    42    B
  003   3     03    ETX (end of text)           103   67    43    C
  004   4     04    EOT (end of transmission)   104   68    44    D
  005   5     05    ENQ (enquiry)               105   69    45    E
  006   6     06    ACK (acknowledge)           106   70    46    F
  007   7     07    BEL '\a' (bell)             107   71    47    G
  010   8     08    BS  '\b' (backspace)        110   72    48    H
  011   9     09    HT  '\t' (horizontal tab)   111   73    49    I
  012   10    0A    LF  '\n' (new line)         112   74    4A    J
  013   11    0B    VT  '\v' (vertical tab)     113   75    4B    K
  014   12    0C    FF  '\f' (form feed)        114   76    4C    L
  015   13    0D    CR  '\r' (carriage ret)     115   77    4D    M
  016   14    0E    SO  (shift out)             116   78    4E    N
  017   15    0F    SI  (shift in)              117   79    4F    O
  020   16    10    DLE (data link escape)      120   80    50    P
  021   17    11    DC1 (device control 1)      121   81    51    Q
  022   18    12    DC2 (device control 2)      122   82    52    R
  023   19    13    DC3 (device control 3)      123   83    53    S
  024   20    14    DC4 (device control 4)      124   84    54    T
  025   21    15    NAK (negative ack.)         125   85    55    U
  026   22    16    SYN (synchronous idle)      126   86    56    V
  027   23    17    ETB (end of trans. blk)     127   87    57    W
  030   24    18    CAN (cancel)                130   88    58    X
  031   25    19    EM  (end of medium)         131   89    59    Y
  032   26    1A    SUB (substitute)            132   90    5A    Z
  033   27    1B    ESC (escape)                133   91    5B    [
  034   28    1C    FS  (file separator)        134   92    5C    \  '\\'
  035   29    1D    GS  (group separator)       135   93    5D    ]
  036   30    1E    RS  (record separator)      136   94    5E    ^
  037   31    1F    US  (unit separator)        137   95    5F    _
  040   32    20    SPACE                       140   96    60    `
  041   33    21    !                           141   97    61    a
  042   34    22    "                           142   98    62    b
  043   35    23    #                           143   99    63    c
  044   36    24    $                           144   100   64    d
  045   37    25    %                           145   101   65    e
  046   38    26    &                           146   102   66    f
  047   39    27    '                           147   103   67    g
  050   40    28    (                           150   104   68    h
  051   41    29    )                           151   105   69    i
  052   42    2A    *                           152   106   6A    j
  053   43    2B    +                           153   107   6B    k
  054   44    2C    ,                           154   108   6C    l
  055   45    2D    -                           155   109   6D    m
  056   46    2E    .                           156   110   6E    n
  057   47    2F    /                           157   111   6F    o
  060   48    30    0                           160   112   70        
  061   49    31    1                           161   113   71    q
  062   50    32    2                           162   114   72    r
  063   51    33    3                           163   115   73    s
  064   52    34    4                           164   116   74    t
  065   53    35    5                           165   117   75    u
  066   54    36    6                           166   118   76    v
  067   55    37    7                           167   119   77    w
  070   56    38    8                           170   120   78    x
  071   57    39    9                           171   121   79    y
  072   58    3A    :                           172   122   7A    z
  073   59    3B    ;                           173   123   7B    {
  074   60    3C    <                           174   124   7C    |
  075   61    3D    =                           175   125   7D    }
  076   62    3E    >                           176   126   7E    ~
  077   63    3F    ?                           177   127   7F    DE   
```
## HEX 
- Hexadecimal representation is a base-16 numbering system using digits 0-9 and A-F, useful for compactly expressing binary data in a human-readable format in computing and programming contexts.
- Hexadecimal character represents 4 bits (or half a byte). 

## Base64 
- Base64 is a binary-to-text encoding scheme that represents binary data in a 64-character ASCII string.
- It's commonly used for encoding binary data for safe text-based transmission or storage.
- One character of a Base64 string encodes 6 binary digits (bits), and so 4 characters of Base64 encode three 8-bit bytes

