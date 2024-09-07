# Introduction

Web Reconnaissance This process involves systematically and meticulously collecting information about a target website or web application.

### Active Reconnaisance 

| Technique            | Description                                                                 | Example                                                                                       | Tools                          | Risk of Detection                                                                 |
|----------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------|----------------------------------------------------------------------------------|
| Port Scanning        | Identifying open ports and services running on the target.                  | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS).                | Nmap, Masscan, Unicornscan    | High: Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls. |
| Vulnerability Scanning | Probing the target for known vulnerabilities, such as outdated software or misconfigurations. | Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities. | Nessus, OpenVAS, Nikto        | High: Vulnerability scanners send exploit payloads that security solutions can detect. |
| Network Mapping      | Mapping the target's network topology, including connected devices and their relationships. | Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure. | Traceroute, Nmap              | Medium to High: Excessive or unusual network traffic can raise suspicion.         |
| Banner Grabbing      | Retrieving information from banners displayed by services running on the target. | Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version. | Netcat, curl                  | Low: Banner grabbing typically involves minimal interaction but can still be logged. |
| OS Fingerprinting    | Identifying the operating system running on the target.                     | Using Nmap's OS detection capabilities (-O) to determine if the target is running Windows, Linux, or another OS. | Nmap, Xprobe2                 | Low: OS fingerprinting is usually passive, but some advanced techniques can be detected. |
| Service Enumeration  | Determining the specific versions of services running on open ports.        | Using Nmap's service version detection (-sV) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0. | Nmap                          | Low: Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts. |
| Web Spidering        | Crawling the target website to identify web pages, directories, and files.  | Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources. | Burp Suite Spider, OWASP ZAP Spider, Scrapy (customisable) | Low to Medium: Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic. |

### Passive Reconnaisannce

| Technique              | Description                                                                 | Example                                                                                       | Tools                          | Risk of Detection                                                                 |
|------------------------|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------|----------------------------------------------------------------------------------|
| Search Engine Queries  | Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles. | Searching Google for "[Target Name] employees" to find employee information or social media profiles. | Google, DuckDuckGo, Bing, and specialised search engines (e.g., Shodan) | Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts. |
| WHOIS Lookups          | Querying WHOIS databases to retrieve domain registration details.           | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers. | whois command-line tool, online WHOIS lookup services | Very Low: WHOIS queries are legitimate and do not raise suspicion. |
| DNS                    | Analysing DNS records to identify subdomains, mail servers, and other infrastructure. | Using dig to enumerate subdomains of a target domain.                                         | dig, nslookup, host, dnsenum, fierce, dnsrecon | Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious. |
| Web Archive Analysis   | Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information. | Using the Wayback Machine to view past versions of a target website to see how it has changed over time. | Wayback Machine | Very Low: Accessing archived versions of websites is a normal activity. |
| Social Media Analysis  | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook. | Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools | Very Low: Accessing public social media profiles is not considered intrusive. |
| Code Repositories      | Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities. | Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities. | GitHub, GitLab | Very Low: Code repositories are meant for public access, and searching them is not suspicious. |

# WHOIS 
WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. 

```
whois inlanefreight.com
```
1) Domain Name: The domain name itself (e.g., example.com)
2) Registrar: The company where the domain was registered (e.g., GoDaddy, Namecheap)
3) Registrant Contact: The person or organization that registered the domain.
4) Administrative Contact: The person responsible for managing the domain.
5) Technical Contact: The person handling technical issues related to the domain.
6) Creation and Expiration Dates: When the domain was registered and when it's set to expire.
7) Name Servers: Servers that translate the domain name into an IP address.

- Identify key personnel: Records often reveal the names, emails, and phone numbers responsible for the domain
- Discover network infrastructure: name servers and Ip addresses provides the target network structure.
- Historical data analysis: [WhoisFreaks](https://whoisfreaks.com/) can reveal changes in ownership, contact info or tech details over time.

### Utilising WHOIS
```
sudo apt update
sudo apt install whois -y
whois facebook.com
```
# DNS
The Domain Name System (DNS) acts as the internet's GPS, guiding your online journey from memorable landmarks (domain names) to precise numerical coordinates (IP addresses).

When you enter a domain name, your computer first checks its memory (cache) for the IP address. If it doesn’t find it, it asks a __DNS resolver__, usually from your ISP. The resolver checks its own cache and, if needed, asks a __rootnameserver__, which directs it to the __TLD name server__ (like .com or .org). The TLD server then points to the __authoritative name server__ for the specific domain. This server provides the correct IP address, which the resolver sends back to your computer. Your computer then connects to the web server, and you can start browsing.

The hosts file is a simple text file used to map hostnames to IP addresses, providing a manual method of domain name resolution. The hosts file is located in __C:\Windows\System32\drivers\etc\hosts__ on Windows and in __/etc/hosts__ on Linux
| Record Type | Full Name                | Description                                                        | Zone File Example                                      |
|-------------|--------------------------|--------------------------------------------------------------------|--------------------------------------------------------|
| A           | Address Record           | Maps a hostname to its IPv4 address.                               | www.example.com. IN A 192.0.2.1                        |
| AAAA        | IPv6 Address Record      | Maps a hostname to its IPv6 address.                               | www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334  |
| CNAME       | Canonical Name Record    | Creates an alias for a hostname, pointing it to another hostname.  | blog.example.com. IN CNAME webserver.example.net.      |
| MX          | Mail Exchange Record     | Specifies the mail server(s) responsible for handling email for the domain. | example.com. IN MX 10 mail.example.com.               |
| NS          | Name Server Record       | Delegates a DNS zone to a specific authoritative name server.      | example.com. IN NS ns1.example.com.                    |
| TXT         | Text Record              | Stores arbitrary text information, often used for domain verification or security policies. | example.com. IN TXT "v=spf1 mx -all" (SPF record)     |
| SOA         | Start of Authority Record| Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400 |
| SRV         | Service Record           | Defines the hostname and port number for specific services.        | _sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com. |
| PTR         | Pointer Record           | Used for reverse DNS lookups, mapping an IP address to a hostname. | 1.2.0.192.in-addr.arpa. IN PTR www.example.com.        |


## Digging DNS

| Command                     | Description                                                                                       |
|-----------------------------|---------------------------------------------------------------------------------------------------|
| `dig domain.com`            | Performs a default A record lookup for the domain.                                                |
| `dig domain.com A`          | Retrieves the IPv4 address (A record) associated with the domain.                                 |
| `dig domain.com AAAA`       | Retrieves the IPv6 address (AAAA record) associated with the domain.                              |
| `dig domain.com MX`         | Finds the mail servers (MX records) responsible for the domain.                                   |
| `dig domain.com NS`         | Identifies the authoritative name servers for the domain.                                         |
| `dig domain.com TXT`        | Retrieves any TXT records associated with the domain.                                             |
| `dig domain.com CNAME`      | Retrieves the canonical name (CNAME) record for the domain.                                       |
| `dig domain.com SOA`        | Retrieves the start of authority (SOA) record for the domain.                                     |
| `dig @1.1.1.1 domain.com`   | Specifies a specific name server to query; in this case 1.1.1.1                                    |
| `dig +trace domain.com`     | Shows the full path of DNS resolution.                                                            |
| `dig -x 192.168.1.1`        | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name.         |
| `dig +short domain.com`     | Provides a short, concise answer to the query.                                                    |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output.                                         |
| `dig domain.com ANY`        | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482). |

### Header
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449: This line indicates the type of query (QUERY), the successful status (NOERROR), and a unique identifier (16449) for this specific query.

;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0: This describes the flags in the DNS header:

qr: Query Response flag - indicates this is a response.
rd: Recursion Desired flag - means recursion was requested.
ad: Authentic Data flag - means the resolver considers the data authentic. The remaining numbers indicate the number of entries in each section of the DNS response: 1 question, 1 answer, 0 authority records, and 0 additional records. ;; WARNING: recursion requested but not available: This indicates that recursion was requested, but the server does not support it.

### Question Section
;google.com. IN A: This line specifies the question: “What is the IPv4 address (A record) for google.com?”


### Answer Section
google.com. 0 IN A 142.251.47.142: This is the answer to the query. It indicates that the IP address associated with google.com is 142.251.47.142. The ‘0’ represents the TTL (time-to-live), indicating how long the result can be cached before being refreshed.


### Footer
;; Query time: 0 msec: This shows the time it took for the query to be processed and the response to be received (0 milliseconds).

;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP): This identifies the DNS server that provided the answer and the protocol used (UDP).

;; WHEN: Thu Jun 13 10:45:58 SAST 2024: This is the timestamp of when the query was made.

;; MSG SIZE rcvd: 54: This indicates the size of the DNS message received (54 bytes).

An opt pseudosection can sometimes exist in a dig query. This is due to Extension Mechanisms for DNS (EDNS), which allows for additional features such as larger message sizes and DNS Security Extensions (DNSSEC) support.

## Subdomains
When exploring DNS records, we've primarily focused on the main domain (e.g., example.com) and its associated information. However, beneath the surface of this primary domain lies a potential network of subdomains. 
Subdomains often host valuable information and resources that aren't directly linked from the main website. This can include: Development and Staging Environments ,Hidden Login Portals, Legacy Applications,Sensitive Information. 

__Active Subdomain Enumeration__: 1) Use DNS Zone Transfer (mostly fail due to high security) 2)  brute-force enumeration, which involves systematically testing a list of potential subdomain names against the target domain. Tools like dnsenum, ffuf, and gobuster 

__Passive Subdomain Enumeration__: 1) Certificate Transparency (CT) logs, public repositories of SSL/TLS certificates. These certificates often include a list of associated subdomains in their Subject Alternative Name (SAN) field. 2)  search engines like Google or DuckDuckGo. By employing specialised search operators (e.g., site:)

### Subdomain Bruteforcing

| Tool        | Description                                                                                           |
|-------------|-------------------------------------------------------------------------------------------------------|
| dnsenum     | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains. |
| fierce      | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface. |
| dnsrecon    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customizable output formats. |
| amass       | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| assetfinder | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans. |
| puredns     | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.   |

__dnsenum__ performs 1) DNS Record Enumeration (A,AAAA,NS,MX,TXT records) 2) Zone Transfer Attempt 3) Subdomain enumeration 4) Google Scraping (Google search results to find additional subdomains that might not be listed in DNS records) 5) Reverse Lookup reverse DNS lookups to identify domains associated with a given IP 6) WHOIS Lookups (WHOIS queries to gather information about domain ownership and details)

```
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```
-r recursive subdomain brute-forcing (if a subdomain is found it will try to enumerate subdomains of the subdomain)
