# Content
- [requests](#requests)
- [BeautifulSoup](#BeautifulSoup)
- [urllibparse](#urllibparse)
- 


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

# using threads

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

- using httpx

```python
import threading
import httpx

# Function to perform an HTTP GET request
def fetch_url(url):
    try:
        response = httpx.get(url)
        print(f"URL: {url}, Status Code: {response.status_code}")
    except httpx.RequestError as exc:
        print(f"An error occurred while requesting {url}: {exc}")

# List of URLs to fetch
urls = [
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://jsonplaceholder.typicode.com/posts/2",
    "https://jsonplaceholder.typicode.com/posts/3"
]

# Create and start threads
threads = []
for url in urls:
    thread = threading.Thread(target=fetch_url, args=(url,))
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()

print("All requests have been completed.")

```
