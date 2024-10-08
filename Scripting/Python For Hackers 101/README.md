# Content
- [requests](#requests)
- [BeautifulSoup](#BeautifulSoup)
- [urllibparse](#urllibparse)
- [Httpx](#httpx)
- [Threading](#threading)
    - [using threading](#using-threading)
    - [using asyncio](#using-asyncio) 


## requests
used to easy make http requests 


1. **Basic GET Request:**
    ```python
    import requests
    
    response = requests.get('https://www.example.com')
    print(response.text)
    ```

2. **Passing Parameters:**
    You can pass query parameters easily using the `params` parameter.
    ```python
    params = {'param1': 'value1', 'param2': 'value2'}
    response = requests.get('https://www.example.com', params=params)
    ```

3. **Custom Headers:**
    You can set custom headers in the request.
    ```python
    headers = {'User-Agent': 'Custom User Agent'}
    response = requests.get('https://www.example.com', headers=headers)
    ```

4. **Response Content:**
    You can access the content of the response.
    ```python
    print(response.content)  # Raw content (bytes)
    print(response.text)     # Decoded content (string)
    ```

5. **Response Status and Headers:**
    ```python
    print(response.status_code)
    print(response.headers)
    ```

6. **Handling Errors:**
    ```python
    response = requests.get('https://www.example.com')
    if response.status_code == 200:
        # Process the response
    else:
        print(f"Request failed with status code {response.status_code}")
    ```

7. **POST Request:**
    ```python
    data = {'key': 'value'}
    response = requests.post('https://www.example.com/post_endpoint', data=data)
    ```

8. **JSON Response:**
    ```python
    response = requests.get('https://api.example.com/data')
    data = response.json()
    ```

9. **Timeouts:**
    Set timeouts to prevent requests from hanging indefinitely.
    ```python
    response = requests.get('https://www.example.com', timeout=5)
    ```

10. **Handling Sessions:**
    For maintaining session data (cookies, headers) across requests.
    ```python
    session = requests.Session()
    response1 = session.get('https://www.example.com')
    response2 = session.get('https://www.example.com/some_data')
    ```

11. **File Download:**
    ```python
    response = requests.get('https://www.example.com/somefile.pdf')
    with open('file.pdf', 'wb') as f:
        f.write(response.content)
    ```

12. **Streamed Downloads:**
    For large files, use streaming to avoid loading the whole content into memory.
    ```python
    response = requests.get('https://www.example.com/large_file.zip', stream=True)
    with open('large_file.zip', 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    ```

## BeautifulSoup 
BeautifulSoup is a Python library used for parsing HTML and XML documents ,searching and modfying on it  

1. **Basic HTML Parsing:**
```python
from bs4 import BeautifulSoup

html = '<html><body><p>Hello, BeautifulSoup!</p></body></html>'
soup = BeautifulSoup(html, 'html.parser')
```
2. **Navigating the Parse Tree:**
```python
title = soup.title
paragraph = soup.body.p
parent_div = div.next_sibling
next_sibling = paragraph.next_sibling
```
3. **Finding Elements:**
```python
divs = soup.find_all('div')
first_paragraph = soup.find('p')
anchors = soup.find_all('a' , href=True)  // with href attribute 
```
4. **Parsing from URL:**
```python
url = 'https://www.example.com'
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')
```
5. **Extracting Text:**
```python
paragraph_text = paragraph.get_text()
```
6. **Parsing XML:**
```python
soup = BeautifulSoup(xml_content, 'lxml')
```

## urllib.parse
The `urllib.parse` module in Python is used for parsing URLs and performing URL encoding and decoding.

1. **URL Parsing:**

```python
from urllib.parse import urlparse

url = 'https://www.example.com/page?param=value#section'
parsed_url = urlparse(url)
print(parsed_url)
```

2. **URL Joining:**
```python
from urllib.parse import urljoin

base_url = 'https://www.example.com'
relative_url = '/page'
complete_url = urljoin(base_url, relative_url)
print(complete_url)
```

3. **URL Encoding:**
```python
from urllib.parse import quote

unencoded_string = 'Hello, World!'
encoded_string = quote(unencoded_string)
print(encoded_string)
```

4. **URL Decoding:**
```python
from urllib.parse import unquote

encoded_string = 'Hello%2C%20World%21'
decoded_string = unquote(encoded_string)
print(decoded_string)
```

5. **Query String Parsing:**
```python
from urllib.parse import parse_qs

query_string = 'param1=value1&param2=value2'
query_params = parse_qs(query_string)
print(query_params)
```

6. **Query String Encoding:**
```python
from urllib.parse import urlencode

params = {'param1': 'value1', 'param2': 'value2'}
encoded_query_string = urlencode(params)
print(encoded_query_string)
```

7. **URL Component Unquoting:**
```python
from urllib.parse import unquote_plus

encoded_string = 'Hello%2C+World%21'
decoded_string = unquote_plus(encoded_string)
print(decoded_string)
```

8. **URL Component Quoting:**
```python
from urllib.parse import quote_plus

unencoded_string = 'Hello, World!'
encoded_string = quote_plus(unencoded_string)
print(encoded_string)
```

# Httpx 

```python
import httpx
from io import BytesIO

def main():
    # Create a synchronous HTTP client
    client = httpx.Client()

    # Case 1: Simple GET request
    try:
        response = client.get("https://jsonplaceholder.typicode.com/posts/1")
        print("GET Response:", response.text)
    except Exception as e:
        print("Error in GET request:", e)



    # Case 2: Simple POST request with form data
    form_data = {"title": "foo", "body": "bar", "userId": "1"}
    try:
        response = client.post("https://jsonplaceholder.typicode.com/posts", data=form_data)
        print("POST Form Data Response:", response.text)
    except Exception as e:
        print("Error in POST request with form data:", e)


    # Case 3: POST request with multipart form data and a file from disk
    try:
        with open("/path/to/file.txt", "rb") as file:
            files = {"fileField": ("file.txt", file)}
            response = client.post("https://jsonplaceholder.typicode.com/posts", data=form_data, files=files)
            print("POST Multipart with File Response:", response.text)
    except Exception as e:
        print("Error in POST request with file from disk:", e)


    # Case 4: POST request with multipart form data and a file from memory buffer
    file_content = b"This is the content of the in-memory file"
    file_reader = BytesIO(file_content)
    try:
        files = {"fileField": ("in-memory-file.txt", file_reader)}
        response = client.post("https://jsonplaceholder.typicode.com/posts", data=form_data, files=files)
        print("POST Multipart with In-Memory File Response:", response.text)
    except Exception as e:
        print("Error in POST request with in-memory file:", e)


    # Case 5: Setting a single custom header
    try:
        response = client.get("https://jsonplaceholder.typicode.com/posts/1", headers={"Authorization": "Bearer your_token_here"})
        print("GET with Custom Header Response:", response.text)
    except Exception as e:
        print("Error in GET request with custom header:", e)



    # Case 6: Setting multiple custom headers
    custom_headers = {
        "Authorization": "Bearer your_token_here",
        "Content-Type": "application/json",
        "X-Custom-Header": "custom_value"
    }
    try:
        response = client.get("https://jsonplaceholder.typicode.com/posts/1", headers=custom_headers)
        print("GET with Multiple Custom Headers Response:", response.text)
    except Exception as e:
        print("Error in GET request with multiple custom headers:", e)



    # Case 7: Setting redirect behavior
    try:
        response = client.get("http://httpbin.org/redirect/3", follow_redirects=False)
        print("GET without Redirect Response:", response.text)
    except Exception as e:
        print("Error in GET request with no redirect:", e)

    try:
        response = client.get("http://httpbin.org/redirect/3")
        print("GET with Redirect Response:", response.text)
    except Exception as e:
        print("Error in GET request with redirect:", e)



    # Case: Allow redirects
    try:
        response = client.get("http://httpbin.org/redirect/3", follow_redirects=True)
        print("GET Response with 1 Redirect Allowed:", response.text)
    except Exception as e:
        print("Error in GET request with 1 redirect allowed:", e)





    # Case 8: Handling the response and checking for words or status codes
    try:
        response = client.get("https://jsonplaceholder.typicode.com/posts/1")
        if "userId" in response.text:
            print("The word 'userId' was found in the response!")
        else:
            print("The word 'userId' was NOT found in the response.")
        
        if response.status_code == 200:
            print("Success! Status code is 200.")
        else:
            print("Request failed with status code:", response.status_code)
    except Exception as e:
        print("Error handling response:", e)


    # Close the client
    client.close()

if __name__ == "__main__":
    main()
```

- with asyncio
```python
import httpx
import asyncio
from io import BytesIO

async def main():
    async with httpx.AsyncClient() as client:
        # Case 1: Simple GET request
        try:
            response = await client.get("https://jsonplaceholder.typicode.com/posts/1")
            print("GET Response:", response.text)
        except Exception as e:
            print("Error in GET request:", e)



        # Case 2: Simple POST request with form data
        form_data = {"title": "foo", "body": "bar", "userId": "1"}
        try:
            response = await client.post("https://jsonplaceholder.typicode.com/posts", data=form_data)
            print("POST Form Data Response:", response.text)
        except Exception as e:
            print("Error in POST request with form data:", e)



        # Case 3: POST request with multipart form data and a file from disk
        try:
            with open("/path/to/file.txt", "rb") as file:
                files = {"fileField": ("file.txt", file)}
                response = await client.post("https://jsonplaceholder.typicode.com/posts", data=form_data, files=files)
                print("POST Multipart with File Response:", response.text)
        except Exception as e:
            print("Error in POST request with file from disk:", e)



        # Case 4: POST request with multipart form data and a file from memory buffer
        file_content = b"This is the content of the in-memory file"
        file_reader = BytesIO(file_content)
        try:
            files = {"fileField": ("in-memory-file.txt", file_reader)}
            response = await client.post("https://jsonplaceholder.typicode.com/posts", data=form_data, files=files)
            print("POST Multipart with In-Memory File Response:", response.text)
        except Exception as e:
            print("Error in POST request with in-memory file:", e)



        # Case 5: Setting a single custom header
        try:
            response = await client.get("https://jsonplaceholder.typicode.com/posts/1", headers={"Authorization": "Bearer your_token_here"})
            print("GET with Custom Header Response:", response.text)
        except Exception as e:
            print("Error in GET request with custom header:", e)



        # Case 6: Setting multiple custom headers
        custom_headers = {
            "Authorization": "Bearer your_token_here",
            "Content-Type": "application/json",
            "X-Custom-Header": "custom_value"
        }
        try:
            response = await client.get("https://jsonplaceholder.typicode.com/posts/1", headers=custom_headers)
            print("GET with Multiple Custom Headers Response:", response.text)
        except Exception as e:
            print("Error in GET request with multiple custom headers:", e)



        # Case 7: Setting redirect behavior
        try:
            response = await client.get("http://httpbin.org/redirect/3", follow_redirects=False)
            print("GET without Redirect Response:", response.text)
        except Exception as e:
            print("Error in GET request with no redirect:", e)

        try:
            response = await client.get("http://httpbin.org/redirect/3")
            print("GET with Redirect Response:", response.text)
        except Exception as e:
            print("Error in GET request with redirect:", e)



        # Case: Allow redirects 
        try:
            response = await client.get("http://httpbin.org/redirect/3", follow_redirects=True)
            print("GET Response with 1 Redirect Allowed:", response.text)
        except Exception as e:
            print("Error in GET request with 1 redirect allowed:", e)



        # Case 8: Handling the response and checking for words or status codes
        try:
            response = await client.get("https://jsonplaceholder.typicode.com/posts/1")
            if "userId" in response.text:
                print("The word 'userId' was found in the response!")
            else:
                print("The word 'userId' was NOT found in the response.")
            
            if response.status_code == 200:
                print("Success! Status code is 200.")
            else:
                print("Request failed with status code:", response.status_code)
        except Exception as e:
            print("Error handling response:", e)

# Run the main function
asyncio.run(main())

```


# Threading

## using threading

```python
import threading
import time

def print_numbers():
    for i in range(5):
        print(f"Number: {i}")
        time.sleep(1)  # Simulate a time-consuming task

def print_letters():
    for letter in 'abcde':
        print(f"Letter: {letter}")
        time.sleep(1)  # Simulate a time-consuming task

# Create threads
thread1 = threading.Thread(target=print_numbers)
thread2 = threading.Thread(target=print_letters)

# Start threads
thread1.start()
thread2.start()

# Wait for both threads to complete
thread1.join()
thread2.join()

print("Both threads have finished execution.")
```


## using asyncio 
- `async def`: Defines a coroutine.
- `await`: Pauses the coroutine until the awaited task finishes.
- `asyncio.run()`: function automatically creates and runs an event loop

```python
import asyncio

async def say_hello():
    print("Hello")
    await asyncio.sleep(1)  # Simulate an asynchronous delay
    print("World")

# To run the coroutine
asyncio.run(say_hello())
```

- `asyncio.create_task()`: to schedule a coroutine without waiting for its completion.

```python
async def print_message():
    await asyncio.sleep(2)
    print("Message after 2 seconds")

async def main():
    task = asyncio.create_task(print_message())  # Create a task
    print("Task started")
    await task  # Wait for the task to complete

asyncio.run(main())
```

- `asyncio.gather()`: is used to run multiple coroutines concurrently. It returns the results of all coroutines when they have all completed.
```python
async def fetch_data_1():
    await asyncio.sleep(2)
    return "Data 1"

async def fetch_data_2():
    await asyncio.sleep(1)
    return "Data 2"

async def main():
    results = await asyncio.gather(fetch_data_1(), fetch_data_2())
    print(results)  # Outputs: ['Data 1', 'Data 2']

asyncio.run(main())
```


