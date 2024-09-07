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

## Digging DNS
