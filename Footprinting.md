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
### Shodan

Shodan can be used to find devices that are connected permenantley to the internet like IOT devices. It searches the internet for open ports and other filters based on the IPs provided (FTP, SSH, SNMP, Telnet, RTSP, or SI).

```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
for i in $(cat ip-addresses.txt);do shodan host $i;done
```
### Dig

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

### Google Dork AWS
```
intext:CompanyName inurl:amazonaws.com
```
### Google Dork Azure
```
intext:CompanyName inurl:blob.core.windows.net
```
## Passive Enumeration

### domain.glass

Third party providers such as [domain.glass](https://domain.glass/) can give information on the company infrastructure. It can also give cloudflare assessment 'Safe' which means there is a security measure (level 2 in the methadology).

### GrayHatWarfare

[GrayHatWarfare](https://buckets.grayhatwarfare.com/)This can be used to different cloud storage resources alternative to google dorking method above. Can even sort and filter by file format.

Companies can make mistakes, private ssh keys can be uploaded which can give us a way to access machines.

### Employee Enumeration (staff)

Use [LinkedIn](https://www.linkedin.com/) or [Xing](https://www.xing.com/) to find employees in the organisation. The experience section usually shows which methadologies or frameworks they use. Job postings from the company can also give us information on the frameworks and capabilities of a an employee.

[Github](https://github.com/boomcamp/django-security) can be used to find repositories of the employee. Which could have misconfigurations eg. Django OWASP10. Sometimes employees can have hardcoded security keys(JWT Token), Personal email addresses etc in the code which can be used.

# FTP Enumeration

FTP Runs on application layer of TCP/IP protocol. In FTP 2 connection channels are opened Control channel (port21) and Data channel (port 20).

__Active FTP Mode__:
1) In active mode, the client initiates the connection.
2) The client sends a PORT command to the server, specifying a client-side port for data transfer.
3) The server then connects back to the client on that specified port.
However, if the client is behind a firewall, the server’s connection attempt may be blocked.

__Passive FTP Mode__:
1)In passive mode, the server announces a port for data transfer.
2 The client sends a PASV command to the server, requesting a port.
3) The server responds with a random port number for the client to use.
4) The client initiates the data connection to that port, bypassing firewall issues.

### TFTP
TFTP does use user authentication. Runs on UDP based application layer recovery. TFTP operating exclusively in directories and with files that have been shared with all users and can be read and written globally (can be read based on read and write permissions).

## Default configuration on FTP

Configuration can be found in /etc/vsftpd.conf for vsFTPd.

| Setting                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| listen                 | Run from inetd or as a standalone daemon?                                                     |
| listen_ipv6            | Listen on IPv6?                                                                               |
| anonymous_enable       | Enable Anonymous access?                                                                       |
| local_enable           | Allow local users to login?                                                                    |
| dirmessage_enable      | Display active directory messages when users go into certain directories?                       |
| use_localtime          | Use local time?                                                                                |
| xferlog_enable         | Activate logging of uploads/downloads?                                                          |
| connect_from_port_20   | Connect from port 20?                                                                          |
| secure_chroot_dir      | Name of an empty directory                                                                     |
| pam_service_name       | This string is the name of the PAM service vsftpd will use.                                      |
| rsa_cert_file          | The location of the RSA certificate to use for SSL encrypted connections (cert file).           |
| rsa_private_key_file   | The location of the RSA certificate to use for SSL encrypted connections (private key file).    |
| ssl_enable             | Enable SSL?                                                                                    |

 /etc/ftpusers holds the users that are denied access to FTP even if the users exist.

 ## Dangerous Settings

 Anonymous authentication This is often used to allow everyone on the internal network to share files and data without accessing each other's computers.
 | Setting                    | Description                                                                                   |
|----------------------------|-----------------------------------------------------------------------------------------------|
| anonymous_enable           | Allowing anonymous login?                                                                      |
| anon_upload_enable         | Allowing anonymous to upload files?                                                             |
| anon_mkdir_write_enable    | Allowing anonymous to create new directories?                                                    |
| no_anon_password           | Do not ask anonymous for password?                                                               |
| anon_root                  | Directory for anonymous.                                                                       |
| write_enable               | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?              |

Once connected through anonymous usually we get STATUS:220 with banner of the FTP server. This information could hold the service version. We can download all the files that are available to anonymous login.

### Anonymous Login
```
ftp 10.129.14.136
```
use __ls__ command to list files and status command to get settings of the FTP server. For more information on packet tracing and communication use __debug__ and __trace__ command.

### Hiding IDs and Recursive Listing

| Setting                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| dirmessage_enable      | Show a message when users first enter a new directory?                                         |
| chown_uploads          | Change ownership of anonymously uploaded files?                                                |
| chown_username         | User who is given ownership of anonymously uploaded files.                                      |
| local_enable           | Enable local users to login?                                                                   |
| chroot_local_user      | Place local users into their home directory?                                                    |
| chroot_list_enable     | Use a list of local users that will be placed in their home directory?                            |
| hide_ids               | All user and group information in directory listings will be displayed as "ftp".                |
| ls_recurse_enable      | Allows the use of recursive listings.                                                           |

__hide_ids=YES__ setting will not show UID and GUID. Identification of which rights these files have been written and uploaded will be difficult. This setting is a security feature to prevent local usernames from being revealed. If usernames are found it can help in methods like brute force.  In reality, [fail2ban](https://en.wikipedia.org/wiki/Fail2ban) solutions are now a standard implementation of any infrastructure that logs the IP address and blocks all access to the infrastructure after a certain number of failed login attempts.

__ls_recurse_enable=YES__ This is often set on the vsFTPd server to have a better overview of the FTP directory structure.

## Download and Upload FTP files

__Download a perticular file__
```
get Important\ Notes.txt
```
__Download all available files__

```
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```
This can alert the system as usually no employee downloads all the files.  wget will create a directory with the name of the IP address of our target. 

use ```tree .``` command to see the directory structure. Use ```put file.txt``` to upload files.

## Footprinting the Service

Use nmap NSE scripts to enumerate FTP. 

Find NSE ftp scripts
```
find / -type f -name ftp* 2>/dev/null | grep scripts
```
As we already know, the FTP server usually runs on the standard TCP port 21, which we can scan using Nmap. We also use the version scan (-sV), aggressive scan (-A), and the default script scan (-sC) against our target.
```
sudo nmap -sV -p21 -sC -A 10.129.14.136
```
1) Default Script Scan in Nmap:
 Nmap uses fingerprints, responses, and standard ports to scan services. 
 For example, the __ftp-anon__ script checks if an FTP server allows anonymous access.
 The __ftp-syst__ script reveals FTP server status and version.
2) Tracing NSE Scripts:
 Use __--script-trace__ in Nmap scans to see commands, ports, and responses.

## Service Interaction

__netcat__ or __telnet__ can be used to interact with the FTP server.

```
nc -nv 10.129.14.136 21
```
```
 telnet 10.129.14.136 21
```
## Openssl ftp connect

If FTP server runs with __TLS/SSL__ encryption. __Openssl__ client can be used to communicated with FTP server.
```
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
The __SSL__ certificate can show us valuable information such  as hostname, email address,etc.

# SMB Enumeration 

Server Message Block (SMB) is a client-server protocol it regulates access to files, directories and other network resources eg printers,routers, or interfaces.
Samba implements the Common Internet File System (CIFS) network protocol. CIFS allows samba to communicate with newer systems. When we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over TCP ports 137, 138, 139, but CIFS uses TCP port 445 only.
### Default configuration file
```
cat /etc/samba/smb.conf | grep -v "#\|\;"
```
SMB server config can be overwritten in individual shares setting.

### Restart SAMBA
```
sudo systemctl restart smbd
```
### SMB client connect 
```
smbclient -N -L //10.129.14.128
```
### SMB connect share
```
smbclient //10.129.14.128/sharename
```
### Download files from SMB
```
get prep-prod.txt
```
Samba acts as the service through which users connect using their credentials. The domain controller(Windows NT) verifies these credentials and grants access only if the user is authorized(NTDS.dit and SAM are password files), allowing them to access shared resources.
From admin __smbstatus__ command provides way to see connections and which share the connection is been made to.

### Nmap SMB enumeration
```
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
### RPCclient SMB enumeration
The Remote Procedure Call (RPC) is a concept and, therefore, also a central tool to realize operational and work-sharing structures in networks and client-server architectures.
```
rpcclient -U "" 10.129.14.128
```
| Query            | Description                                                   |
|------------------|---------------------------------------------------------------|
| srvinfo          | Server information.                                           |
| enumdomains      | Enumerate all domains that are deployed in the network.       |
| querydominfo     | Provides domain, server, and user information of deployed domains. |
| netshareenumall  | Enumerates all available shares.                              |
| netsharegetinfo <share> | Provides information about a specific share.           |
| enumdomusers     | Enumerates all domain users.                                  |
| queryuser <RID> , querygroup <RID>| Provides information about a specific user. retrieve information from the entire group|

### RPCclient Brute Forcing User RIDs
```
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
Alternative to this would be a Python script from __Impacket__ called __samrdump.py__.
```
samrdump.py 10.129.14.128
```
__SMBMap__ and __CrackMapExec__ tools are also widely used and helpful for the enumeration of SMB services.
```
smbmap -H 10.129.14.128
```
```
crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```
### enum4linux-ng
Enum4linux
__Installation__
```
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
```
__Enumeration__ 
```
./enum4linux-ng.py 10.129.14.128 -A
```
# NFS Enumeration
Network File System (NFS) is to access file systems over a network as if they were local. NFS is used between Linux and Unix systems. __NFSv3__ Used IP based authentication (insecure) and __NFSv4__ uses user authntication.

### Default configuraion 
__/etc/exports__ file contains a table of physical filesystems on an NFS server accessible by the clients.Specify who can access them and what permissions they have. 
| Option            | Description                                                                                           |
|-------------------|-------------------------------------------------------------------------------------------------------|
| rw                | Read and write permissions.                                                                           |
| ro                | Read-only permissions.                                                                                |
| sync              | Synchronous data transfer (a bit slower).                                                             |
| async             | Asynchronous data transfer (a bit faster).                                                            |
| secure            | Ports above 1024 will not be used.                                                                    |
| insecure          | Ports above 1024 will be used.                                                                        |
| no_subtree_check  | Disables the checking of subdirectory trees.                                                          |
| root_squash       | Assigns all permissions of files owned by root (UID/GID 0) to the UID/GID of anonymous, preventing root from accessing files on an NFS mount. |

### ExportFS
Create NFS for subnet with sync and no subtree option for 10.129.14.0/24.
```
echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
systemctl restart nfs-kernel-server 
exportfs
```
### Nmap NFS Enumeration 
```
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```
### Show available NFS shares 
```
showmount -e 10.129.14.128
```
### Mounting NFS Share
```
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```
### List Contents with Usernames & Group Names
```
ls -l mnt/nfs/
```
### List Contents with UIDs & GUIDs
```
ls -n mnt/nfs/
```
Effect of root_squash:
even if the UID and GID match the owner of a file on the NFS share, the NFS server treats the client’s root user as an anonymous user.

To circumvent __root_squash__  we ssh with less privledge account to the target machine upload a shell with suid bit and change the owner to higher privledged account.

# DNS 
DNS is a system for resolving computer names into IP addresses, and it does not have a central database. 
| **Server Type**              | **Description**                                                                                                                                                                                                                       |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **DNS Root Server**          | The root servers of the DNS are responsible for the top-level domains (TLD). They are only requested if the name server does not respond. They link domain and IP address and are coordinated by ICANN. There are 13 root servers globally. |
| **Authoritative Nameserver** | Authoritative name servers hold authority for a particular zone and provide binding information. If they cannot answer a query, the root name server takes over.                                                                  |
| **Non-authoritative Nameserver** | Non-authoritative name servers do not hold responsibility for a DNS zone. They gather information on DNS zones using recursive or iterative querying.                                                                          |
| **Caching DNS Server**       | Caching DNS servers store information from other name servers for a specified period. The duration is determined by the authoritative name server.                                                                                 |
| **Forwarding Server**        | Forwarding servers forward DNS queries to another DNS server.                                                                                                                                                                         |
| **Resolver**                 | Resolvers perform name resolution locally in a computer or router but are not authoritative DNS servers.                                                                                                                               |

IT security professionals apply DNS over TLS (DoT) or DNS over HTTPS (DoH) here. In addition, the network protocol DNSCrypt also encrypts the traffic between the computer and the name server.

| **DNS Record** | **Description**                                                                                                                                                             |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **A**          | Returns an IPv4 address of the requested domain.                                                                                                                           |
| **AAAA**       | Returns an IPv6 address of the requested domain.                                                                                                                           |
| **MX**         | Returns the responsible mail servers for the domain.                                                                                                                        |
| **NS**         | Returns the DNS servers (nameservers) of the domain.                                                                                                                        |
| **TXT**        | Contains various information, such as validation for Google Search Console or SSL certificates. Also used for SPF and DMARC entries to validate mail traffic and protect from spam. |
| **CNAME**      | Serves as an alias for another domain name. For example, a CNAME record for www.hackthebox.eu points to the same IP as hackthebox.eu.                                        |
| **PTR**        | Performs reverse lookup by converting IP addresses into valid domain names.                                                                                                 |
| **SOA**        | Provides information about the DNS zone and the email address of the administrative contact.                                                                              |

### SOA Record lookup
```
dig soa www.inlanefreight.com
```
The dot (.) is replaced by an at sign (@) in the email address.

### Default Configuration
DNS servers work with three different types of configuration files:
1) local DNS configuration files
2) zone files
3) reverse name resolution files

DNS server Bind9 is often used in linux. 
The local configuration files are usually:
1) named.conf.local - Defines specific domain zones that the server will manage.
2) named.conf.options - Contains global settings that apply to the server as a whole, such as where to forward DNS requests that the server can't resolve locally.
3) named.conf.log - Manages logging settings for the server to keep track of DNS queries and server activity.

### Local DNS Configuration
```
cat /etc/bind/named.conf.local
```
Here we define the different zones. These zones are divided into individual files called Zone Files. Zone File follows BIND format. one SOA record and at least one NS record is needed.

### Zone file lookup 
```
cat /etc/bind/db.domain.com
```
