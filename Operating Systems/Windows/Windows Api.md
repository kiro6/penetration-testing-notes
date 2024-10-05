

### Windows API Types

- **HANDLE**:
    - **Definition**: A handle is an opaque reference to a system resource, such as a file or a process. It abstracts the underlying resource and is usually represented as `void*`.
    - **Defined in typedef**:
      ```cpp
      typedef void* HANDLE;
      ```

- **DWORD**:
    - **Definition**: Double word, a 32-bit unsigned integer (`unsigned long`), used frequently to store sizes, flags, and other quantities.
    - **Defined in typedef**:
      ```cpp
      typedef unsigned long DWORD;
      ```

- **LPSTR**:
    - **Definition**: A "Long Pointer to a String," meaning it's a pointer to a mutable (non-constant) null-terminated string (`char*`).
    - **Defined in typedef**:
      ```cpp
      typedef char* LPSTR;
      ```

- **LPCSTR**:
    - **Definition**: A "Long Pointer to a Constant String," meaning it's a pointer to a constant null-terminated string (`const char*`).
    - **Defined in typedef**:
      ```cpp
      typedef const char* LPCSTR;
      ```

- **LPWSTR**:
    - **Definition**: A "Long Pointer to a Wide String," meaning it's a pointer to a mutable null-terminated wide-character string (`wchar_t*`), used for Unicode strings.
    - **Defined in typedef**:
      ```cpp
      typedef wchar_t* LPWSTR;
      ```

- **LPCWSTR**:
    - **Definition**: A "Long Pointer to a Constant Wide String," meaning it's a pointer to a constant null-terminated wide-character string (`const wchar_t*`).
    - **Defined in typedef**:
      ```cpp
      typedef const wchar_t* LPCWSTR;
      ```

- **LPVOID**:
    - **Definition**: A "Long Pointer to Void," meaning it's a pointer to a memory block of unspecified type (`void*`), used for generic data manipulation.
    - **Defined in typedef**:
      ```cpp
      typedef void* LPVOID;
      ```

- **BOOL**:
    - **Definition**: A 32-bit integer used to represent Boolean values, typically `TRUE` (non-zero) or `FALSE` (zero).
    - **Defined in typedef**:
      ```cpp
      typedef int BOOL;
      ```

- **BYTE**:
    - **Definition**: An 8-bit unsigned integer, used for raw byte data (equivalent to `unsigned char`).
    - **Defined in typedef**:
      ```cpp
      typedef unsigned char BYTE;
      ```

- **WORD**:
    - **Definition**: A 16-bit unsigned integer, used for small integer values (equivalent to `unsigned short`).
    - **Defined in typedef**:
      ```cpp
      typedef unsigned short WORD;
      ```

- **LPOVERLAPPED**:
    - **Definition**: A pointer to an `OVERLAPPED` structure, which is used in asynchronous I/O operations to provide additional information.
    - **Defined in typedef**:
      ```cpp
      typedef OVERLAPPED* LPOVERLAPPED;
      ```

- **LPDWORD**:
    - **Definition**: A pointer to a `DWORD`, commonly used to return sizes or counts (e.g., number of bytes written).
    - **Defined in typedef**:
      ```cpp
      typedef DWORD* LPDWORD;
      ```

- **LPSECURITY_ATTRIBUTES**:
    - **Definition**: A pointer to a `SECURITY_ATTRIBUTES` structure, which specifies security attributes for objects like files and processes.
    - **Defined in typedef**:
      ```cpp
      typedef SECURITY_ATTRIBUTES* LPSECURITY_ATTRIBUTES;
      ```

- **LPTSTR**:
    - **Definition**: A pointer to a string that can be either `char*` or `wchar_t*`, depending on whether Unicode support is enabled.
    - **Defined in typedef**:
      ```cpp
      typedef TCHAR* LPTSTR;
      ```

- **LPVOID**:
    - **Definition**: A pointer to a memory location without a specific type, allowing for flexibility in the data type being pointed to.
    - **Defined in typedef**:
      ```cpp
      typedef void* LPVOID;
      ```

- **PVOID**:
    - **Definition**: A pointer to a void, similar to `LPVOID`, often used interchangeably.
    - **Defined in typedef**:
      ```cpp
      typedef void* PVOID;
      ```

- **LPHANDLE**:
    - **Definition**: A pointer to a handle, typically used when you need to pass a handle by reference to an API function.
    - **Defined in typedef**:
      ```cpp
      typedef HANDLE* LPHANDLE;
      ```
