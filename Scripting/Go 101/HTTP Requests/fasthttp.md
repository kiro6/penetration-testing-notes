# fasthttp

### make GET request
```go
package main

import (
	"fmt"

	"github.com/valyala/fasthttp"
)

func main() {
	// Create a new fasthttp client
	client := &fasthttp.Client{}

	// Make a GET request
	url := "https://google.com"
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)

	// Send the request
	if err := client.Do(req, resp); err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print response status code
	fmt.Println("Status code:", resp.StatusCode())

	// Print response body
	fmt.Println("Response body:", string(resp.Body()))
}

```

### Post request with json data
```go
package main

import (
	"fmt"
	"github.com/valyala/fasthttp"
)

func main() {
	// Create a new fasthttp client
	client := &fasthttp.Client{}

	// Define the request body
	requestBody := []byte(`{"key": "value"}`)

	// Create a new fasthttp request object
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Set the request method, URI, body, and content type header
	req.SetRequestURI("https://api.example.com/data")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/json")
	req.SetBody(requestBody)

	// Create a new fasthttp response object
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Send the request
	if err := client.Do(req, resp); err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print response status code
	fmt.Println("Status code:", resp.StatusCode())

	// Print response body
	fmt.Println("Response body:", string(resp.Body()))
}
```

```
```
