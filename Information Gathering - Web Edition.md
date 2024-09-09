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

# Subdomains
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


### DNS Zone Transfer

1. **Zone Transfer Request (AXFR)**
   - The secondary DNS server initiates the process by sending a zone transfer request to the primary server.
   - This request typically uses the AXFR (Full Zone Transfer) type.

2. **SOA Record Transfer**
   - Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record.
   - The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.

3. **DNS Records Transmission**
   - The primary server then transfers all the DNS records in the zone to the secondary server, one by one.
   - This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.

4. **Zone Transfer Complete**
   - Once all records have been transmitted, the primary server signals the end of the zone transfer.
   - This notification informs the secondary server that it has received a complete copy of the zone data.

5. **Acknowledgement (ACK)**
   - The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data.
   - This completes the zone transfer process.

if DNS server is not configured properly and allows for zone transfers we can gain Subdomains(including development enviornments) , IP Addresses, Name Server Records: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.
__Remediation__:  Modern DNS servers are typically configured to allow zone transfers only to trusted secondary servers.

```
dig axfr @nsztm1.digi.ninja zonetransfer.me
```
# Virtual Hosts 

Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting. Virtual hosting is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address(using __HTTP HEADER__). 

Difference between subdomain and virtual host

__Subdomains__: Extensions of a main domain (like blog.example.com) used to organize different parts of a website.
__Virtual Hosts__ (VHosts): Server configurations that allow multiple websites or apps to be hosted on one server, each with its own settings.

If a virtual host does not have a DNS record, you can still access it by modifying the hosts file on your local machine. The hosts file allows you to map a domain name to an IP address manually(/etc/hosts).
![image](https://github.com/user-attachments/assets/1c9b3443-6907-43ea-b63a-4d82582d6d57)

Different types of vHosts
1) Name-Based Virtual Hosting: HTTP Host header to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses.
2) IP-Based Virtual Hosting: assigns a unique IP address to each website hosted on the server. Doesn't rely on the Host header.
3) Port-Based Virtual Hosting: One website might be accessible on port 80, while another is on port 8080.(different websites on different ports)

### VHOSTS Enumeration
```
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
Make sure you assign an IP to the domain if it is not recognisable by dns. In the command above do not forgot about changing the port as well. You can find the ports through nmap scans(initial stage).
```
sudo sh -c "echo '94.237.63.201 inlanefreight.htb' >> /etc/hosts"
```

# Certificate Transparency Logs

Certificate Transparency (CT) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. 

crt.sh offers a convenient web interface, you can also leverage its API for automated searches directly from your terminal.

```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```
jq -r '.[] | select(.name_value | contains("dev")) | .name_value': This part filters the JSON results, selecting only entries where the name_value field (which contains the domain or subdomain) includes the string "dev." The -r flag tells jq to output raw strings. -u orders it alphabetically.

# Fingerprinting

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application.

Techniques : Banner Grabbing, Analysing HTTP Headers: HTTP headers transmitted with every web page request and response contain a wealth of information. Probing for Specific Responses: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. Analysing Page Content: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies.

| Tool       | Description                                                        | Features                                                                 |
|------------|--------------------------------------------------------------------|--------------------------------------------------------------------------|
| Wappalyzer | Browser extension and online service for website technology profiling. | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| BuiltWith  | Web technology profiler that provides detailed reports on a website's technology stack. | Offers both free and paid plans with varying levels of detail.            |
| WhatWeb    | Command-line tool for website fingerprinting.                      | Uses a vast database of signatures to identify various web technologies.  |
| Nmap       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting. |
| Netcraft   | Offers a range of web security services, including website fingerprinting and security reporting. | Provides detailed reports on a website's technology, hosting provider, and security posture. |
| wafw00f    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs). | Helps determine if a WAF is present and, if so, its type and configuration. |

### Banner Grabbing
```
curl -I inlanefreight.com
```
-I is header. Version number might be available. Location: tag in output is a redirect grab other banners.

### Wafw00f
Web Application Firewalls (WAFs) are security solutions designed to protect web applications from various attacks.
```
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com
```
If protected then we might need to adapt techniques to bypass.

### Nikto
Nikto is a powerful open-source web server scanner. In addition to its primary function as a vulnerability assessment tool, Nikto's fingerprinting capabilities provide insights into a website's technology stack.

__Installation__
```
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```
__Command__
```
nikto -h inlanefreight.com -Tuning b
```
-h is target host -Tuning b to only run the Software Identification modules.

In output - Headers: Several non-standard or insecure headers were found, including a missing Strict-Transport-Security header and a potentially insecure x-redirect-by header.

# Crawling
Crawling, often called spidering, is the automated process of systematically browsing the World Wide Web. Similar to how a spider navigates its web, a web crawler follows links from one page to another, collecting information.

Breadth-First Crawling (BFS) - 
How it works: Imagine you’re exploring a building floor by floor. You check all the rooms on the first floor before moving to the second floor.
Depth-First Crawling (DFS)
How it works: Now, imagine you’re exploring the same building, but this time you go as deep as possible into one room, then the next, and so on. You go down one hallway until you can’t go any further, then backtrack and start down the next hallway.

From crawling you extract : 
1) Links (Internal and External): These are the fundamental building blocks of the web, connecting pages within a website (internal links) and to other websites (external links).
2) Comments: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information.
3) Metadata: Metadata refers to data about data. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates.
4) Sensitive Files: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website.(eg /files)

## Robots.txt
robots.txt is a simple text file placed in the root directory of a website (e.g., www.example.com/robots.txt). It adheres to the Robots Exclusion Standard, guidelines for how web crawlers should behave when visiting a website.
__User-agent__: This line specifies which crawler or bot the following rules apply to. A wildcard (*) indicates that the rules apply to all bots.
__Directives__: These lines provide specific instructions to the identified user-agent.
### robots.txt in Web Reconnaissance
__Uncovering Hidden Directories__: Disallowed paths in robots.txt often point to directories or files that they want private
__Mapping Website Structure__: By analyzing the allowed and disallowed paths, security professionals can create a rudimentary map of the website's structure.
__Detecting Crawler Traps__: Some websites intentionally include "honeypot" directories in robots.txt to lure malicious bots. 

## Well-Known URIs
/.well-known/ path on a web server, centralizes a website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms.
| URI Suffix                     | Description                                                                 | Status      | Reference                                                                                                      |
|--------------------------------|-----------------------------------------------------------------------------|-------------|---------------------------------------------------------------------------------------------------------------|
| security.txt                   | Contains contact information for security researchers to report vulnerabilities. | Permanent   | RFC 9116                                                     |
| /.well-known/change-password   | Provides a standard URL for directing users to a password change page.       | Provisional | WebAppSec Change Password URL |
| openid-configuration           | Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol. | Permanent   | OpenID Connect Discovery 1.0                     |
| assetlinks.json                | Used for verifying ownership of digital assets (e.g., apps) associated with a domain. | Permanent   | Digital Asset Links     |
| mta-sts.txt                    | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security. | Permanent   | RFC 8461                                                     |
The information from the `openid-configuration` endpoint provides multiple exploration opportunities:

- **Endpoint Discovery**:
  - **Authorization Endpoint**: URL for user authorization requests.
  - **Token Endpoint**: URL where tokens are issued.
  - **Userinfo Endpoint**: URL providing user information.
  - **JWKS URI**: Reveals the JSON Web Key Set (JWKS) with cryptographic keys.

- **Supported Scopes and Response Types**: Helps map out functionality and limitations.

- **Algorithm Details**: Information about supported signing algorithms for security measures.

Exploring the IANA Registry and experimenting with the various .well-known URIs is an invaluable approach to uncovering additional web reconnaissance opportunities

## Creepy Crawlies

### Scrapy 
__Installation__
```
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
 unzip ReconSpider.zip
```
__Usage__
```
python3 ReconSpider.py http://inlanefreight.com
```
Output in results.json.
| JSON Key        | Description                                           |
|-----------------|-------------------------------------------------------|
| emails          | Lists email addresses found on the domain.            |
| links           | Lists URLs of links found within the domain.          |
| external_files  | Lists URLs of external files such as PDFs.            |
| js_files        | Lists URLs of JavaScript files used by the website.   |
| form_fields     | Lists form fields found on the domain (empty in this example). |
| images          | Lists URLs of images found on the domain.             |
| videos          | Lists URLs of videos found on the domain (empty in this example). |
| audio           | Lists URLs of audio files found on the domain (empty in this example). |
| comments        | Lists HTML comments found in the source code.         |

# Search Engine Discovery

| Operator        | Description                                                         | Example                                                         |
|-----------------|---------------------------------------------------------------------|-----------------------------------------------------------------|
| `site:`         | Limits results to a specific website or domain.                     | `site:example.com`                                              |
| `inurl:`        | Finds pages with a specific term in the URL.                        | `inurl:login`                                                   |
| `filetype:`      | Searches for files of a particular type.                            | `filetype:pdf`                                                  |
| `intitle:`      | Finds pages with a specific term in the title.                      | `intitle:"confidential report"`                                  |
| `intext:` or `inbody:` | Searches for a term within the body text of pages.            | `intext:"password reset"`                                       |
| `cache:`        | Displays the cached version of a webpage (if available).            | `cache:example.com`                                             |
| `link:`         | Finds pages that link to a specific webpage.                        | `link:example.com`                                              |
| `related:`      | Finds websites related to a specific webpage.                       | `related:example.com`                                           |
| `info:`         | Provides a summary of information about a webpage.                  | `info:example.com`                                              |
| `define:`       | Provides definitions of a word or phrase.                           | `define:phishing`                                               |
| `numrange:`     | Searches for numbers within a specific range.                       | `site:example.com numrange:1000-2000`                            |
| `allintext:`    | Finds pages containing all specified words in the body text.        | `allintext:admin password reset`                                |
| `allinurl:`     | Finds pages containing all specified words in the URL.              | `allinurl:admin panel`                                          |
| `allintitle:`   | Finds pages containing all specified words in the title.            | `allintitle:confidential report 2023`                            |
| `AND`           | Narrows results by requiring all terms to be present.               | `site:example.com AND (inurl:admin OR inurl:login)`             |
| `OR`            | Broadens results by including pages with any of the terms.          | `"linux" OR "ubuntu" OR "debian"`                               |
| `NOT`           | Excludes results containing the specified term.                     | `site:bank.com NOT inurl:login`                                 |
| `*` (wildcard)  | Represents any character or word.                                   | `site:socialnetwork.com filetype:pdf user* manual`              |
| `..` (range search) | Finds results within a specified numerical range.                | `site:ecommerce.com "price" 100..500`                           |
| `" "` (quotation marks) | Searches for exact phrases.                                    | `"information security policy"`                                 |
| `-` (minus sign) | Excludes terms from the search results.                             | `site:news.com -inurl:sports`                                   |

### Google Dorking
Google Dorking, also known as Google Hacking, is a technique that leverages the power of search operators to uncover sensitive information, security vulnerabilities, or hidden content on websites, using Google Search.
__Finding Login Pages__
- `site:example.com inurl:login`
- `site:example.com (inurl:login OR inurl:admin)`

__Identifying Exposed Files__
- `site:example.com filetype:pdf`
- `site:example.com (filetype:xls OR filetype:docx)`

__Uncovering Configuration Files__
- `site:example.com inurl:config.php`
- `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)

__Locating Database Backups__
- `site:example.com inurl:backup`
- `site:example.com filetype:sql`

# Web Archives

__The Wayback Machine__ is a digital archive of the World Wide Web and other information on the Internet. Founded by the Internet Archive, a non-profit organization, it has been archiving websites since 1996.

Crawling: The Wayback Machine uses bots to systematically browse the web and download copies of webpages by following links.

Archiving: Downloaded pages, along with resources like images and scripts, are stored in the Wayback Machine. Each snapshot is tied to a specific date and time, with archiving done at intervals based on the site’s update frequency.

Accessing: Users can view archived snapshots by entering a URL and selecting a date. The Wayback Machine allows browsing of pages, searching within archived content, and downloading sites for offline use.

Use of webarchieve during Recon: 
Uncovering Hidden Assets and Vulnerabilities: Discover old pages, directories, and files not visible on the current site, which might reveal sensitive info or security issues.

Tracking Changes and Identifying Patterns: Compare historical snapshots to see how a website has evolved, including changes in structure, content, and potential vulnerabilities.

Gathering Intelligence: Use archived content for OSINT to gain insights into past activities, marketing strategies, and technology choices.

Stealthy Reconnaissance: Viewing archived snapshots is a passive method that doesn’t interact directly with the target, making it less detectable.

# Automating recon
Automating web reconnaissance tasks can significantly enhance efficiency and accuracy, allowing you to gather information at scale and identify potential vulnerabilities more rapidly.

Automated tools offers __Efficiency__ , __Scalability__: Automation allows you to scale your reconnaissance efforts across a large number of targets, __Consistency__: Automated tools follow predefined rules and procedures, __Comprehensive Coverage__: Automation can be programmed to perform a wide range of reconnaissance tasks(dns,subdomain enumeration,port scanning,etc), __Integration__: Many automation frameworks allow for easy integration with other tools and platforms.

### Recon Frameworks 

__FinalRecon__ 
__Recon-ng__ (It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities).
__theHarvester__: Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database.
__SpiderFoot__: An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles.
__OSINT Framework__: A collection of various tools and resources for open-source intelligence gathering.

### FinalRecon

It offers 
- **Header Info:** Reveals server details and security issues.
- **Whois Lookup:** Shows domain registration and contact info.
- **SSL Certificate:** Checks validity and issuer.
- **Crawler:**
  - **HTML/CSS/JS:** Extracts links and resources.
  - **Links:** Maps site structure.
  - **Images, robots.txt, sitemap.xml:** Finds crawl paths and structure.
  - **JS Links, Wayback Machine:** Uncovers hidden links and historical data.
- **DNS Enumeration:** Queries DNS records, including DMARC.
- **Subdomain Enumeration:** Uses multiple sources to find subdomains.
- **Directory Enumeration:** Finds hidden directories and files.
- **Wayback Machine:** Analyzes historical website data.

__Installation__
```
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```
| Option        | Argument     | Description                                  |
|---------------|--------------|----------------------------------------------|
| `-h, --help`  |              | Show the help message and exit.              |
| `--url`       | URL          | Specify the target URL.                      |
| `--headers`   |              | Retrieve header information for the target URL. |
| `--sslinfo`   |              | Get SSL certificate information for the target URL. |
| `--whois`     |              | Perform a Whois lookup for the target domain. |
| `--crawl`     |              | Crawl the target website.                    |
| `--dns`       |              | Perform DNS enumeration on the target domain. |
| `--sub`       |              | Enumerate subdomains for the target domain.  |
| `--dir`       |              | Search for directories on the target website. |
| `--wayback`   |              | Retrieve Wayback URLs for the target.        |
| `--ps`        |              | Perform a fast port scan on the target.      |
| `--full`      |              | Perform a full reconnaissance scan on the target. |

__Usage__
```
./finalrecon.py --headers --whois --url http://inlanefreight.com
```
