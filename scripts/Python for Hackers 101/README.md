# Here i mention the most important python libraries for hackers
## - [requests](#requests)
## - [BeautifulSoup](#BeautifulSoup)


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
```pyhton
paragraph_text = paragraph.get_text()
```
6. **Parsing XML:**
```python
soup = BeautifulSoup(xml_content, 'lxml')
```
