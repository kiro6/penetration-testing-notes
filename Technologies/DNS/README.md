
# Content
- [DNS concept](#dns-concept)
- [Types of DNS Name Servers](#types-of-dns-name-servers)
- [Resource Records](#resource-records)
- [SOA (Start of Authority) Records](#soa-start-of-authority-records)
- [DNS zone conf syntax](#dns-zone-conf-syntax)

## DNS concepts:

**Resource Record:**
- A domain name, usually a fully qualified domain name, is the first part of a Resource Record.

**TTL (Time-To-Live):**
- In seconds, the Time-To-Live (TTL) defaults to the minimum value specified in the SOA record.

**Record Class:**

- Internet (IN): The most widely used and default class for DNS resource records. Used for standard DNS operations on the Internet. Most DNS records (A, AAAA, MX, CNAME, TXT, etc.) are created within the IN class.
- Hesiod (HS): Less commonly used, associated with the Hesiod naming system for Unix-like systems and additional naming and directory service lookups.
- Chaos (CH): Less commonly used, associated with the Chaosnet networking protocol for special information queries and debugging.

**Namespace:**

- Refers to the hierarchical structure that organizes and identifies domain names.

**Domain Name:**

- A human-readable label used to access resources on the internet. Represents a specific entity or organization and typically consists of two or more labels separated by dots.
- Domain names are registered with domain registrars and provide a unique identity for websites, email servers, and other internet services.

**DNS Zone:**

- A portion of the DNS namespace managed by a specific set of DNS servers.
- Encompasses all DNS resource records associated with a particular domain or subdomain.
- Each domain or subdomain has its own DNS zone with its set of DNS records, defined in a zone file.

**Zone Transfers:**

- Full Zone Transfer (AXFR): Transfers the complete zone file from the primary server to the secondary server, updating the entire zone regardless of changes.
- Incremental Zone Transfer (IXFR): Transfers only the changes in the zone since the last transfer, reducing bandwidth usage and improving efficiency.

**DNS Resolver:**

- A component or software library responsible for initiating DNS queries to resolve domain names into IP addresses.
- Interacts with DNS name servers to obtain the necessary information.
- Maintains a cache of recently resolved DNS records to speed up subsequent queries and reduce the load on DNS servers.

**DNS Name Server:**

- A crucial component of the DNS infrastructure that stores and manages DNS records for a specific zone or domain.
- When a DNS resolver sends a query for a particular domain name, the DNS name server provides the resolver with the corresponding DNS records.


### Types of DNS Name Servers

**Authoritative Name Server:**

- An authoritative name server is responsible for storing and serving the DNS records for a specific domain or zone.
- It holds the definitive information for that domain and provides responses to DNS queries with accurate and up-to-date information.

**Recursive Resolver:**

- A recursive resolver, also known as a caching resolver, is a DNS resolver that interacts with multiple DNS name servers to resolve domain names on behalf of client devices or applications.
- It performs the entire DNS resolution process by sending queries to authoritative name servers, following the DNS hierarchy, and returning the resolved information to the client.

**Forwarding Name Server:**

- A forwarding name server is configured to forward DNS queries to another DNS resolver or name server.
- Instead of resolving the queries itself, it passes the queries to a designated upstream resolver.
- This can be useful for offloading the DNS resolution workload to more capable or specialized servers.


DNS server === Name Server

### Resource Records

**TTL:**

- The TTL value specifies the amount of time (in seconds) that a DNS resolver or client should cache the DNS records obtained from the DNS server before checking for updated records.
- It indicates how long the DNS information can be considered valid and cached by other systems.

**Name Servers (NS):**

- The distributed database is bound together by NS Records. They are in charge of a zone's authoritative name server and the authority for a child zone to a name server.

**IPv4 Addresses (A):**

- The A record is only a mapping between a hostname and an IP address. 'Forward' zones are those with A records.

**Pointer (PTR):**

- The PTR record is a mapping between an IP address and a hostname. 'Reverse' zones are those that have PTR records.

**Canonical Name:**

- An alias hostname is mapped to an A record hostname using the CNAME record.

**Mail Exchange (MX):**

- The MX record identifies a host that will accept emails for a specific host.
- A priority value has been assigned to the specified host.
- Multiple MX records can exist on the same host, and a prioritized list is made consisting of the records for a specific host.

**TEXT(TXT):** 

- record provides arbitrary text information for the domain.

**Start Of Authority:** 

- It should be first in a zone file because it indicates the start of a zone. (SOA)

- Each zone can only have one SOA record, and additionally, it contains the zone's values, such as a serial number and multiple expiration timeouts.
- EX :
```d
 subdomain.example.com  
     $TTL 3600  
     @   IN  SOA   ns1.example.com. admin.example.com. (  
                 2023062201  ; Serial number  
                 3600        ; Refresh  
                 1800        ; Retry  
                 604800      ; Expire  
                 86400       ; Minimum TTL  
                 )
```


### SOA (Start of Authority) Records:

An SOA (Start of Authority) record is an essential part of a DNS zone file and provides important information about the zone's configuration and management. It includes the following fields:

**Primary Name Server (NS):**

- This field specifies the primary authoritative name server for the zone.
- It indicates the DNS server responsible for serving the zone's DNS records and managing updates to the zone.
- For example: ns1.example.com.

**Responsible Person's Email Address (Email):**

- This field specifies the email address of the responsible person or administrator overseeing the zone.
- It is typically written with a dot replaced by an "@" symbol.
- For example: admin.example.com.

**Serial Number:**

- The serial number is a unique identifier for the zone's DNS records.
- It is typically a numeric value and is incremented each time the zone's records are updated.
- In the given example, the serial number is "2023062201", which suggests that it was last updated or modified on June 22, 2023.
- The serial number helps in determining the freshness of DNS data during zone transfers between DNS servers.

**Retry:**

- The retry value specifies the amount of time (in seconds) that secondary DNS servers should wait before attempting to retry a failed zone transfer or refresh attempt.
- If a secondary DNS server fails to contact the authoritative DNS server during the refresh interval, it will wait for the retry interval to elapse before making another attempt.
- The retry value is typically shorter than the refresh value to ensure timely retries.
- For example, a retry value of 1800 seconds (30 minutes) means the secondary DNS server will wait for 30 minutes before retrying a failed zone transfer or refresh.

**Refresh:**

- The refresh value indicates how often (in seconds) secondary DNS servers should check the authoritative DNS server for updates.
- It specifies the interval at which secondary servers should attempt to refresh their copies of the zone's records from the primary authoritative server.
- In the provided example with a refresh value of 3600 seconds (1 hour), the secondary DNS servers will contact the authoritative server to update their copies of the zone's records at least once every hour.

**Expire:**

- The expire value sets the maximum time (in seconds) that secondary DNS servers can use a zone's data without successfully refreshing it from the authoritative server.
- If a secondary server fails to refresh the zone within the specified expire interval, it will consider the zone expired and stop responding to DNS queries for that zone.
- In the provided configuration, the expire value is set to 604800 seconds (7 days).

**Minimum TTL (Negative TTL):**

- The Minimum TTL (Negative TTL) is a value that specifies how long a negative DNS response, indicating the non-existence of a DNS record, should be cached by DNS resolvers or clients.
- It is used when a query is made for a resource record that does not exist. The Minimum TTL determines the caching duration for negative responses, such as "NXDOMAIN" or "NODATA" responses.
- This value is separate from the TTL values of actual existing DNS records and is typically a lower value.
- It ensures that DNS resolvers or clients cache the negative response for a specified duration before attempting to query the authoritative DNS server again for the same non-existent record.



## DNS zone conf syntax

- The $ORIGIN directive sets the origin for the zone to "example.com." This means that any domain names specified without a trailing dot (.) will be considered relative to "example.com."

- "@" symbol represents the origin or the current zone name.

**Directives:**
- Lines starting with a dollar sign ($) or at symbol (@) are directives that provide instructions or settings for the zone. 
- Examples include $ORIGIN, which sets the origin for the zone, and $TTL, which sets the default time-to-live value for the zone.

**Records:**
- Records specify the DNS resource records for the domain. In the example, you have various record types, such as SOA, NS, MX, TXT, and A. 
- Each record has a specific purpose and provides different types of information.


- If you don't use a fully qualified domain name, the zone's name where the record is located will be appended to the end of the name.
    - Example:
        - Zone: example.com
        - Domain: [www.example.com](http://www.example.com)
        - If you use "www," the domain will be automatically appended as [www.example.com](http://www.example.com).


## examples :

**zone file for one domain and it's subdomains**

```d
; Zone file for example.com (Primary Name Server)
$TTL 3600
example.com.  IN  SOA  ns1.example.com. admin.example.com. (
                2024013101 ; Serial number
                3600       ; Refresh
                1800       ; Retry
                604800     ; Expire
                3600 )     ; Minimum TTL

; Name Server (NS) records for subdomains
@  IN  NS  ns1.example.com.
   IN  NS  ns2.example.com.

; A records for subdomains
subdomain1  IN  A   192.168.1.30
subdomain2  IN  A   192.168.1.31

; Additional records for other services...

```



**one zone contain more than one domain**

```d
; Zone file for domain1.com
$TTL 3600
domain1.com.  IN  SOA  ns1.domain1.com. admin.domain1.com. (
                2024013101 ; Serial number
                3600       ; Refresh
                1800       ; Retry
                604800     ; Expire
                3600 )     ; Minimum TTL

@  IN  NS  ns1.domain1.com.
   IN  NS  ns2.domain1.com.

www  IN  A   192.168.1.40
mail IN  A   192.168.1.41

; Zone file for domain2.net
$TTL 3600
domain2.net.  IN  SOA  ns1.domain2.net. admin.domain2.net. (
                2024013101 ; Serial number
                3600       ; Refresh
                1800       ; Retry
                604800     ; Expire
                3600 )     ; Minimum TTL

@  IN  NS  ns1.domain2.net.
   IN  NS  ns2.domain2.net.

www  IN  A   192.168.1.50
ftp  IN  A   192.168.1.51
```
