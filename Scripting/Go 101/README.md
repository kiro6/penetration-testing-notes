# Content
- [Variables](#variables)
- [Loops](#loops)
- [if condtions](#if-condtions)
- [packages](#packages)
- [Functions](#functions)
- [custom data types](#custom-data-types)
- [Pointers](#pointers)
- [Pointer receivers vs Value](#pointer-receivers-vs-value)
- [Special Keywords](#special-keywords)
- [HTTP requests](#http-requests)
- [Go Routine](#go-routine)


## 
```shell
go mod init Project   

go run main.go

go build main.go

```

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
- Conditional Initialization
```go
package main

import (
    "fmt"
    "strconv"
)

func parseData(data string) (int, error) {
    return strconv.Atoi(data)
}

func main() {
    if result, err := parseData("456"); err == nil {
        fmt.Println("Parsed result:", result)
    } else {
        fmt.Println("Failed to parse data:", err)
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

# Special Keywords

### defer
- Usage: It's commonly used for resource cleanup, like closing files, releasing locks, or network connections.

```go
package main

import (
	"fmt"
)

func main() {
	defer fmt.Println("This will run at the end!") // Executed last
	fmt.Println("This will run first!")
}
```

### panic
Usage: It's generally discouraged for routine error handling but can be useful in situations where recovery is impossible.
```go
package main

import (
	"fmt"
)

func main() {
	defer fmt.Println("This will not run.")
	panic("Something went wrong!")
}

```

### recover
- Usage: Used in combination with panic to regain control of a panicking program. It allows a program to recover from a panic and continue execution. It must be called inside a defer function.

```go
package main

import (
	"fmt"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()

	fmt.Println("Starting...")
	panic("Oh no!")
}
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

# Go Routine

### Creating a Go Routine
```go
package main

import (
    "fmt"
    "time"
)

func printNumbers() {
    for i := 1; i <= 5; i++ {
        fmt.Println(i)
        time.Sleep(1 * time.Second)
    }
}

func main() {
    go printNumbers() // Start printNumbers as a Go routine
    
    // Main function continues executing concurrently
    fmt.Println("Main function running concurrently")
    
    // Wait for the Go routine to complete
    time.Sleep(6 * time.Second)
}

```

### Communication Between Go Routines

- Bidirectional Channel : `chan int`
- Send-Only Channel: `chan<- int`
- Receive-Only Channel: `<-chan int`

```go
package main

import (
	"fmt"
	"time"
)

// Function to generate numbers and send them to the channel
func generateNumbers(ch chan<- int) { // Send-only channel
	for i := 1; i <= 5; i++ {
		ch <- i
		time.Sleep(1 * time.Second)
	}
	close(ch) // Close the channel when done
}

// Function to receive numbers from the channel
func receiveNumbers(ch <-chan int) { // Receive-only channel
	for num := range ch {
		fmt.Println("Received:", num)
	}
}

func main() {
	ch := make(chan int) // Create a bidirectional channel
	//  ch := make(chan string, 5) // Create a buffered channel with capacity of the channel before it locks further sends.
	go generateNumbers(ch) // Start a goroutine to generate numbers
	receiveNumbers(ch)    // Receive numbers in the main goroutine
}

```

### Synchronizing Go Routines
Sometimes you need to wait for one or more Go routines to complete before continuing. This can be achieved using the `sync.WaitGroup` from the `sync` package.
```go
package main

import (
    "fmt"
    "sync"
    "time"
)

func doWork(id int, wg *sync.WaitGroup) {
    defer wg.Done() // Notify that this Go routine is done
    fmt.Printf("Go routine %d is working\n", id)
    time.Sleep(2 * time.Second)
}

func main() {
    var wg sync.WaitGroup

    for i := 1; i <= 3; i++ {
        wg.Add(1) // Increment the counter
        go doWork(i, &wg) // Start Go routine
    }

    wg.Wait() // Wait for all Go routines to finish
    fmt.Println("All Go routines complete")
}
```

### Handling Panics in Go Routines
```go
package main

import (
    "fmt"
    "runtime"
)

func safeGoRoutine() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from panic:", r)
        }
    }()
    // Code that may panic
    panic("Something went wrong")
}

func main() {
    go safeGoRoutine()
    
    // Wait to ensure the Go routine finishes
    time.Sleep(1 * time.Second)
}

```

### lock objects 
A sync.Mutex is used to lock and unlock access to shared resources. This ensures that only one goroutine can access the shared resource at a time, preventing race conditions.

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

// Define a struct with a Mutex and a shared counter
type Counter struct {
	mu    sync.Mutex
	count int
}

// Increment the counter with locking
func (c *Counter) Increment() {
	c.mu.Lock()         // Lock the mutex
	defer c.mu.Unlock() // Ensure the mutex is unlocked after the function completes
	c.count++
}

// Get the current count with locking
func (c *Counter) Get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func main() {
	counter := &Counter{}

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Launch 10 goroutines that increment the counter
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				counter.Increment()
				time.Sleep(1 * time.Millisecond) // Simulate work
			}
		}()
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Print the final count
	fmt.Println("Final count:", counter.Get())
}

```

