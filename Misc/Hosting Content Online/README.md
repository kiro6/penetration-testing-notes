
## using [beeceptor](https://beeceptor.com/)
- beeceptor is powerful tool which can be used to host content and customize your headers 
- with free plan you have 50 req per day per endpoint

### how to use 
- create endpoint
![Screenshot 2023-08-01 at 12-33-37 Beeceptor - Rest_SOAP API Mocking HTTP Debugger   Proxy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a23e3ff0-f8c3-4042-85a4-99ca639c0b19)

- set a rule
![Screenshot 2023-08-01 at 12-35-28 #dumyy](https://github.com/kiro6/penetration-testing-notes/assets/57776872/d7558afc-da60-459c-8806-70bdb9805714)

- result
```bash
$ curl "https://dumyy.free.beeceptor.com/exp.html"

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
<p>helloooo</p>
</body>
</html>
```


## using webhook.site 
- free
- need no account
- can create custom responses

![Screenshot 2023-11-07 at 07-29-00 Webhook site - Test process and transform emails and HTTP requests](https://github.com/kiro6/penetration-testing-notes/assets/57776872/95205240-47c6-4cb6-98d9-bac9880bcb4b)

- click on edit button in the top right to edit response

![Screenshot 2023-11-07 at 07-29-47 Webhook site - Test process and transform emails and HTTP requests](https://github.com/kiro6/penetration-testing-notes/assets/57776872/7ca14670-0516-4385-b9da-5befffdf6a5a)

## using [ngrok](https://ngrok.com/download)

### how to use 
- make http server on any folder , consider hosting a file named test.txt on the local server
```bash
$ python3 -m http.server 9999
```

- start ngrok to point to http 
```
$ ngrok http 9999
```

- take the url from ngrok to access your local server publicly
```
$ curl "https://7be1-41-45-139-146.ngrok-free.app/test.txt"

testttttttttttttttttttttttttttttttt
```

## using [pastebin](https://pastebin.com/)
- just make a new paste with your content and get the url
- you can not know if the url was vistied or not  

