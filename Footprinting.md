# Enumeration Principles

| No. | Principle                                                   |
|-----|-------------------------------------------------------------|
| 1   | There is more than meets the eye. Consider all points of view. |
| 2   | Distinguish between what we see and what we do not see.     |
| 3   | There are always ways to gain more information. Understand the target. |

# Enumeration Methadology

| Layer               | Description                                                                 | Information Categories                                                                 |
|---------------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| 1. Internet Presence| Identification of internet presence and externally accessible infrastructure.| Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| 2. Gateway          | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare     |
| 3. Accessible Services | Identify accessible interfaces and services that are hosted externally or internally. | Service Type, Functionality, Configuration, Port, Version, Interface                  |
| 4. Processes        | Identify the internal processes, sources, and destinations associated with the services. | PID, Processed Data, Tasks, Source, Destination                                       |
| 5. Privileges       | Identification of the internal permissions and privileges to the accessible services. | Groups, Users, Permissions, Restrictions, Environment                                 |
| 6. OS Setup         | Identification of the internal components and systems setup.                | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files list |

Layer 1 - We find find targets to investigate
Layer 2 - This is what protecting the targets and its interface.
Layer 3 - This is the services the targets offer.
Layer 4 - The processes that are launched by the system. The data exchanged between the processes.
Layer 5 - Each service or process is run with certain priveledges. The priveledges used need to be understood.
Layer 6 - Understanding the host itself the Enviornment. Understanding how the admins maintain the system.

# Domain Enumeration

First point of investigation is the main website. Examine the SSL Certificate of the website usually includes subdomain as well. https://crt.sh/ This source is Certificate Transparency logs. Certificate Transparency is a process that is intended to enable the verification of issued digital certificates for encrypted Internet connections. 
 
### Crt.sh Certificate Transperancy
```
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```
### Crt.sh Unique subdomains 
```
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```
### Crt.sh identify hosts
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```
## Shodan

Shodan can be used to find devices that are connected permenantley to the internet like IOT devices. It searches the internet for open ports and other filters based on the IPs provided (FTP, SSH, SNMP, Telnet, RTSP, or SI).

```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
```
## Dig

Displays dns records related to the domain 
```
dig any inlanefreight.com
```
| Record Type | Description                                                                                                                      |
|-------------|----------------------------------------------------------------------------------------------------------------------------------|
| A records   | We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know. |
| MX records  | The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by Google in our case, we should note this and skip it for now. |
| NS records  | These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider. |
| TXT records | This type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as SPF, DMARC, and DKIM, which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results. |

# Cloud Resources Passsive Enumeration

The use of cloud resources is prevelant in many companies like S3 buckets (AWS), blobs (Azure), cloud storage (GCP), which can be accessed if configured incorrectly.

##  Enumerate Company Hosted Servers
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```
![image](https://github.com/user-attachments/assets/22f50da7-5dea-493a-997f-b2757e7f7120)

In the above image we can see s3 bucket We can find cloud resources through Google Dorking as well.

## Google Dork AWS
```
intext:CompanyName inurl:amazonaws.com
```
## Google Dork Azure
```
intext:CompanyName inurl:blob.core.windows.net
```
## Passive Enumeration

### domain.glass

Third party providers such as [domain.glass](https://domain.glass/) can give information on the company infrastructure. It can also give cloudflare assessment 'Safe' which means there is a security measure (level 2 in the methadology).

###GrayHatWarfare

[GrayHatWarfare](https://buckets.grayhatwarfare.com/)This can be used to different cloud storage resources alternative to google dorking method above. Can even sort and filter by file format.

Companies can make mistakes, private ssh keys can be uploaded which can give us a way to access machines.
