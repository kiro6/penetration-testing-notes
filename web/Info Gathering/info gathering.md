

# tools and websites for Information Gathering



## Passive Information Gathering

| Tool/Website                                   | Purpose                                      |
| ---------------------------------------------- | -------------------------------------------- |
| nslookup                                       | DNS information                              |
| dig                                            | DNS information (provides more details than nslookup) |
| whois                                          | DNS information (check NetRange/CIDR) with whois |
| [viewdns.info](https://viewdns.info/)           | Website for DNS-related information           |
| theHarvester                                   | Subdomain enumeration                        |
| crt.sh                                         | Subdomain enumeration                        |
| censys.io                                      | Subdomain enumeration                        |
| sitereport.netcraft                            | Infrastructure information                   |
| waybackurls                                    | Infrastructure, parameters, and info leaks    |



## Active Information Gathering

| Tool/Website                                   | Purpose                                      |
| ---------------------------------------------- | -------------------------------------------- |
| whatweb                                        | Web scanner                                  |
| Wappalyzer extension                           | Web scanner                                  |
| WafW00f                                        | Web application firewall fingerprinting      |
| [hackertarget.com Zone Transfer](https://hackertarget.com/zone-transfer/) | ZoneTransfers (Website)        |
| nslookup -type=any -query=AXFR domain nameServer | ZoneTransfers (using nslookup command)       |
| fuff                                           | Fuzzing (subdomain, Vhosts discovery, etc.)  |
| cewl                                           | Custom wordlists                             |
| zap, burp                                      | Crawling, scanning                           |
| amass                                          | Mapping                                      |
| spiderfoot                                     | OSINT (Open-Source Intelligence)             |
