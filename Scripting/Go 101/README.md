# Content
- [Variables](#variables)
- [Loops](#loops)
- [if condtions](#if-condtions)
- [packages](#packages)
- [Functions](#functions)
- [custom data types](#custom-data-types)
- [Pointers](#pointers)
- [Pointer receivers vs Value](#pointer-receivers-vs-value)


## Variables
- declare variables types
```go
package main

import "fmt"

func main() {
	var varWithDataType string = "initial value"
	var varWithoutDataType = "initial value"
	varShortCut := "initial value"
	var varWithoutValue string
	fmt.Println(varWithDataType, varWithoutDataType, varShortCut, varWithoutValue)

}
```
- [builtin types](https://pkg.go.dev/builtin#pkg-types)

- arrays and slices
```go
package main

import "fmt"

func main() {

	array := [3]int{1, 2, 3} // array is fixed size
	slice := []int{1, 2, 3}  // slice is dynamic size
	fmt.Println(array, "\n", slice)
	newSlice := append(slice, 4)
	fmt.Print(newSlice)
}
```

- maps
```go
package main

import "fmt"

func main() {

	mapVar := map[int64]string{
		1: "value1",
		2: "value2",
		3: "value3",
	}

	fmt.Println(mapVar)
}

```

## Loops

- while loop
```go
package main

import "fmt"

func main() {

	x := 0
	for x < 10 {
		fmt.Println(x)
		x++
	}
}

```
- for loop
```go
package main

import "fmt"

func main() {

	for i := 0; i < 10; i++ {
		fmt.Println(i)
	}
}
```
- for each
```go
package main

func main() {

	slice := []int{1, 2, 3, 4, 5}

	for i, v := range slice {
		println("index: ", i, " value: ", v)
	}

	for _, v := range slice { //we can use _ to ignore the index or value
		println(" value: ", v)
	}

}
```
## if condtions
```go
package main

func main() {

	value := 10

	if value > 5 {
		println("value is greater than 5")
	} else if value < 5 {
		println("value is less than 5")
	} else {
		println("value is equal to 5")
	}

}
```
## packages 
```go
import (
	"fmt"  // import local package
	"github.com/example/examplepackage" // import external package online with downloading it
)
```
## Functions
- functions declare
```go
package main

import "fmt"

func firstFunc(x string) {
	fmt.Print(x)
}

func seconedFunc(x string) string {
	return x
}

func thirdFunc(x string, z string) (string, string) {
	return x, z
}

func main() {
	firstFunc("Hello World")
	fmt.Println(seconedFunc("Hello World"))
	fmt.Println(thirdFunc("Hello", "World"))
}

```

## custom data types
- create struct (simillar to classes)
```go
// this util.go 
package main

type person struct {
	name string
	age  int
	job  string
}

// this function is like constructor in other languages
func newPerson(name string, age int, job string) *person { // *person is a pointer to a person to make it more efficient
	p := person{name: name, age: age, job: job}
	return &p
}

// this function is like class functions in other languages like java
func (p person) printPerson() {
	println(p.name, p.age, p.job)
}

func (p person) getName() string {
	return p.name
}

func (p *person) setAge(a int) {
	p.age = a
}

// main.go
package main

func main() {

	person := newPerson("John", 30, "Developer")

	person.printPerson()
	person.setAge(90)
	person.printPerson()
}


```

- custom data types using `type`

```
type MyFloat float64

func (f MyFloat) Abs() float64 {
	if f < 0 {
		return float64(-f)
	}
	return float64(f)
}
```

## Pointers 
```go
package main

import "fmt"

func main() {
	var pnt *int

	i := 15

	pnt = &i

	// Address of pnt
	fmt.Println("the Address of pnt", &pnt)
	// Address of i which is stored in pnt
	fmt.Println("Address of i : ", pnt)
	// The value of i which is stored in address that the pnt store it
	fmt.Println("Value of i: ", *pnt)
}

```

```
Pointer Variable               Memory Address (points to)              Stored Value
+--------------+          +--------------------------------+          +-------------+
|      ptr     |  ----->  |  Memory location of the value |  ----->  |   42        |
+--------------+          +--------------------------------+          +-------------+

```


## Pointer receivers vs Value

```go 
package main

type person struct {
	name string
	age  int
}

func (p *person) changeNameWithPointerReciver() {
	p.name = "Bob"
}

func (p person) changeName() {
	p.name = "Bob"
}

func main() {
	p := person{name: "Alice", age: 30}
	println(p.name, p.age)
	p.changeName()
	println(p.name, p.age)
	p.changeNameWithPointerReciver()
	println(p.name, p.age)

}



Alice 30
Alice 30
Bob 30
```

# HTTP requests 

```go
package main

import (
    "bytes"
    "fmt"
    "strings"
    "github.com/go-resty/resty/v2"
)

func main() {
    client := resty.New()

    // Case 1: Simple GET request
    resp, err := client.R().
        Get("https://jsonplaceholder.typicode.com/posts/1")
    if err != nil {
        fmt.Println("Error in GET request:", err)
        return
    }
    fmt.Println("GET Response:", resp.String()) // Print the response body

    // Case 2: Simple POST request with form data (application/x-www-form-urlencoded)
    formData := map[string]string{
        "title":  "foo",
        "body":   "bar",
        "userId": "1",
    }
    resp, err = client.R().
        SetFormData(formData).
        Post("https://jsonplaceholder.typicode.com/posts")
    if err != nil {
        fmt.Println("Error in POST request with form data:", err)
        return
    }
    fmt.Println("POST Form Data Response:", resp.String()) // Print the response body

    // Case 3: POST request with multipart form data and a file from disk
    resp, err = client.R().
        SetMultipartFormData(formData).            // Set normal form fields
        SetFile("fileField", "/path/to/file.txt").  // Attach file from disk
        Post("https://jsonplaceholder.typicode.com/posts")
    if err != nil {
        fmt.Println("Error in POST request with file from disk:", err)
        return
    }
    fmt.Println("POST Multipart with File Response:", resp.String()) // Print the response body

    // Case 4: POST request with multipart form data and a file from memory buffer
    fileContent := []byte("This is the content of the in-memory file")
    fileReader := bytes.NewReader(fileContent)
    resp, err = client.R().
        SetMultipartFormData(formData).                          // Set normal form fields
        SetFileReader("fileField", "in-memory-file.txt", fileReader). // Attach file from buffer
        Post("https://jsonplaceholder.typicode.com/posts")
    if err != nil {
        fmt.Println("Error in POST request with in-memory file:", err)
        return
    }
    fmt.Println("POST Multipart with In-Memory File Response:", resp.String()) // Print the response body

    // Case 5: Setting a single custom header (e.g., Authorization header)
    resp, err = client.R().
        SetHeader("Authorization", "Bearer your_token_here").   // Set Authorization header
        Get("https://jsonplaceholder.typicode.com/posts/1")
    if err != nil {
        fmt.Println("Error in GET request with custom header:", err)
        return
    }
    fmt.Println("GET with Custom Header Response:", resp.String()) // Print the response body

    // Case 6: Setting multiple custom headers at once
    customHeaders := map[string]string{
        "Authorization":   "Bearer your_token_here",
        "Content-Type":    "application/json",
        "X-Custom-Header": "custom_value",
    }
    resp, err = client.R().
        SetHeaders(customHeaders).  // Set multiple headers at once
        Get("https://jsonplaceholder.typicode.com/posts/1")
    if err != nil {
        fmt.Println("Error in GET request with multiple custom headers:", err)
        return
    }
    fmt.Println("GET with Multiple Custom Headers Response:", resp.String()) // Print the response body

    // Case 7: Setting redirect behavior (true or false)
    // Prevent redirects by setting RedirectPolicy to resty.NoRedirectPolicy
    resp, err = client.R().
        SetRedirectPolicy(resty.NoRedirectPolicy()). // Disable redirects
        Get("http://httpbin.org/redirect/3")
    if err != nil {
        fmt.Println("Error in GET request with no redirect:", err)
    } else {
        fmt.Println("GET without Redirect Response:", resp.String()) // Print the response body
    }

    // Allowing redirects by default (Resty allows redirects automatically)
    resp, err = client.R().Get("http://httpbin.org/redirect/3")
    if err != nil {
        fmt.Println("Error in GET request with redirect:", err)
    } else {
        fmt.Println("GET with Redirect Response:", resp.String()) // Print the response body
    }


    // Case: Allow redirects only 1 time
    resp, err := client.R().
        SetRedirectPolicy(resty.FlexibleRedirectPolicy(1)).  // Allow only 1 redirect
        Get("http://httpbin.org/redirect/3")                 // This URL redirects 3 times
    if err != nil {
        fmt.Println("Error in GET request with 1 redirect allowed:", err)
    } else {
        fmt.Println("GET Response with 1 Redirect Allowed:", resp.String())
    }

    // Case: Allow redirects only 2 times
    resp, err = client.R().
        SetRedirectPolicy(resty.FlexibleRedirectPolicy(2)).  // Allow only 2 redirects
        Get("http://httpbin.org/redirect/3")                 // This URL redirects 3 times
    if err != nil {
        fmt.Println("Error in GET request with 2 redirects allowed:", err)
    } else {
        fmt.Println("GET Response with 2 Redirects Allowed:", resp.String())
    }

    // Case 8: Handling the response and checking for words or status codes
    if strings.Contains(resp.String(), "userId") {
        fmt.Println("The word 'userId' was found in the response!")
    } else {
        fmt.Println("The word 'userId' was NOT found in the response.")
    }

    // Checking the status code of the response
    if resp.StatusCode() == 200 {
        fmt.Println("Success! Status code is 200.")
    } else {
        fmt.Println("Request failed with status code:", resp.StatusCode())
    }
}

```
