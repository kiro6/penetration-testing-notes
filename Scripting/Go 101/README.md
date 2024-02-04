# Content

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
func newPerson(name string, age int, job string) person {
	p := person{name: name, age: age, job: job}
	return p
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
