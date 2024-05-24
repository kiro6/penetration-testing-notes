# HTTP

### GET Request
```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Send a GET request to the specified URL
	resp, err := http.Get("https://api.example.com/data")
	if err != nil {
		fmt.Println("Error sending GET request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	// Print the response status code
	fmt.Println("Status code:", resp.StatusCode)

	// Print the response body
	fmt.Println("Response body:", string(body))
}

```

### Post Request
```go
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// Define the request body
	requestBody := []byte(`{"key": "value"}`)

	// Create a new HTTP POST request
	req, err := http.NewRequest("POST", "https://api.example.com/data", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Create a new HTTP client
	client := &http.Client{}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Print response status code
	fmt.Println("Status code:", resp.StatusCode)

	// Print response body
	fmt.Println("Response body:", string(body))
}

```
