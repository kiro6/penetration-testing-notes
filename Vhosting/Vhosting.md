
# Virtual Hosts

A virtual host (vHost) is a feature that allows several websites to be hosted on a single server.
This is an excellent solution if you have many websites and don't want to go through the time-consuming (and expensive) process of setting up a new web server for each one.
Imagine having to set up a different webserver for a mobile and desktop version of the same page.
There are two ways to configure virtual hosts:

- IP-based virtual hosting
- Name-based virtual hosting



## IP-based Virtual Hosting

- IP-based virtual hosting is a method of hosting multiple websites on a single web server using different IP addresses.
- In traditional virtual hosting, multiple websites share the same IP address and are identified based on the domain name specified in the HTTP request.
- IP-based virtual hosting, each website is assigned a unique IP address, allowing the web server to distinguish between them based on the IP address rather than the domain name.

Here's how IP-based virtual hosting works:

**Multiple IP addresses  :** 
- The web server hosting the websites must have multiple IP addresses assigned to it
- Each IP address will be associated with a specific website.

**DNS configuration :**  
- The domain names of the websites need to be configured to point to their respective IP addresses.
- This is typically done by setting up DNS (Domain Name System) records, such as A records, that map the domain name to the corresponding IP address.

**Web server configuration :** 
- The web server software needs to be configured to listen on the assigned IP addresses.
- Each IP address is associated with a specific virtual host configuration, which includes settings such as the document root directory and other website-specific configurations.

**Incoming requests  :** 
- When a user makes a request to one of the hosted websites, the request includes the IP address of the server.
- The web server examines the IP address to determine which virtual host configuration should handle the request.

**Virtual host handling  :** 
- Based on the IP address in the incoming request, the web server selects the appropriate virtual host configuration associated with that IP address.
- The web server then serves the content of the requested website from the corresponding document root directory.




-------------------------------------------------------------
- **IP-based virtual hosting allows for better separation and isolation of websites since each website has its own unique IP address.**
- **It can be useful in scenarios where websites require individual SSL certificates or need to be accessed through specific IP addresses for various reasons.**
-------------------------------------------------------------

## Name-based Virtual Hosting

- Name-based virtual hosting is a method of hosting multiple websites on a single web server using a single IP address.
- Unlike IP-based virtual hosting, where each website has a unique IP address, name-based virtual hosting relies on the domain name specified in the HTTP request to determine which website to serve.

Here's how name-based virtual hosting works:

**Single IP address  :** 
- The web server hosting the websites has only one IP address assigned to it. This IP address is shared among multiple websites.

**DNS configuration  :** 
- The domain names of the websites need to be configured to point to the shared IP address of the web server.
- This is typically done by setting up DNS (Domain Name System) records, such as A records, that map the domain names to the IP address.

**Webserver configuration :** 
- The web server software needs to be configured to handle name-based virtual hosting.
- The server examines the HTTP request's "Host" header, which contains the domain name of the requested website.

**Request routing  :** 
- When a user makes a request to one of the hosted websites, the request includes the domain name in the "Host" header.
- The web server uses this information to determine which virtual host configuration should handle the request.

 **Virtual host handling  :** 
 - Based on the domain name in the "Host" header, the web server selects the appropriate virtual host configuration associated with that domain.
- Each virtual host configuration includes settings such as the document root directory and other website-specific configurations.

**Content serving :** 
- The web server serves the content of the requested website from the corresponding document root directory specified in the selected virtual host configuration.



-------------------------------------------------------------
- **Name-based virtual hosting allows hosting multiple websites on a single IP address, which is more efficient in terms of IP address allocation compared to IP-based virtual hosting.**
- **It is widely used and supported by most web servers and is the default method for hosting websites on shared hosting platforms.**
-------------------------------------------------------------

EX :
- several domain names, such as admin.inlanefreight.htb and backup.inlanefreight.htb, can refer to the same IP.
- Internally on the server, these are separated and distinguished using different folders.
- Using this example, on a Linux server, the vHost admin.inlanefreight.htb could point to the folder /var/www/admin.
- For backup.inlanefreight.htb the folder name would then be adapted and could look something like /var/www/backup.


**VHosts may or may not have public DNS records. !!**

In many cases, many websites would actually have sub-domains that are not public and will not publish them in public DNS records, and hence if we visit them in a browser

```shell
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.10.10
 :: Wordlist         : FUZZ: ./vhosts
 :: Header           : Host: FUZZ.randomtarget.com
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 612
________________________________________________

dev-admin               [Status: 200, Size: 120, Words: 7, Lines: 12]
www                     [Status: 200, Size: 185, Words: 41, Lines: 9]
some                    [Status: 200, Size: 195, Words: 41, Lines: 9]
:: Progress: [12/12] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```
