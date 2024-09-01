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
Reverse Name Resolution Zone Files
```
 cat /etc/bind/db.10.129.14
```
### Dig NS Query 
```
dig ns inlanefreight.htb @10.129.14.128
```
### DIG Version Query
```
dig CH TXT version.bind 10.129.120.85
```
### DIG AXFR Zone Transfer
```
dig axfr inlanefreight.htb @10.129.14.128
```
If the administrator used a subnet for the allow-transfer option for testing purposes or as a workaround solution or set it to any, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

### Dig AXFR subdomain Zone Transfer
```
dig axfr internal.inlanefreight.htb @10.129.14.128
```
### Subdomain Brute Forcing
```
for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```
__DNSenum__ Tool
```
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

# SMTP Enumeration

The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network. 
By default, SMTP servers accept connection requests on port 25. However, newer SMTP servers also use other ports such as TCP port 587. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection. 

![image](https://github.com/user-attachments/assets/024a3728-5784-4778-9712-281be1d3d399)
An extension for SMTP has been developed called Extended SMTP (ESMTP).
ESMTP uses TLS, which is done after the EHLO command by sending STARTTLS.

### SMTP commands

| Command    | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| AUTH PLAIN | AUTH is a service extension used to authenticate the client.                |
| HELO       | The client logs in with its computer name and thus starts the session.      |
| MAIL FROM  | The client names the email sender.                                          |
| RCPT TO    | The client names the email recipient.                                       |
| DATA       | The client initiates the transmission of the email.                         |
| RSET       | The client aborts the initiated transmission but keeps the connection between client and server. |
| VRFY       | The client checks if a mailbox is available for message transfer.           |
| EXPN       | The client also checks if a mailbox is available for messaging with this command. |
| NOOP       | The client requests a response from the server to prevent disconnection due to time-out. |
| QUIT       | The client terminates the session.                                          |
To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, HELO or EHLO.

### Telnet HELO/EHLO
```
telnet 10.129.14.128 25
```
VRFY can be used to enumerate existing mailboxes in the server. CODE 252 user does not exist.
### Telnet - VRFY

```
telnet 10.129.14.128 25
VRFY root
VRFY cry0l1t3
```
### Open Relay Configuration
To prevent the sent emails from being filtered by spam filters and not reaching the recipient, the sender can use a relay server that the recipient trusts. It is an SMTP server that is known and verified by all others. As a rule, the sender must authenticate himself to the relay server before using it.

Administrator misconfigure email server where they allow all ips to use the server so that legitimate email does not get into spam. 
![image](https://github.com/user-attachments/assets/54381149-545a-44c8-bbc8-b62e3b3b791b)

With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties.

### Footprinting SMTP 
```
sudo nmap 10.129.14.128 -sC -sV -p25
```
use the smtp-open-relay NSE script to identify the target SMTP server as an open relay using 16 different tests.
```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

### SMTP User Enumeration 
```
smtp-user-enum -M VRFY -U ./footprinting-wordlist.txt -t STMIP -m 60 -w 20
```
-m is worker processes -w query timeout

# IMAP / POP3

IMAP allows online management of emails directly on the server and supports folder structures.  The protocol is client-server-based and allows synchronization of a local email client with the mailbox on the server, providing a kind of network file system for emails, allowing problem-free synchronization across several independent clients.POP3, on the other hand, does not have the same functionality as IMAP, and it only provides listing, retrieving, and deleting emails as functions at the email server. 

 IMAP works unencrypted and transmits commands, emails, or usernames and passwords in plain text. To ensure security mail servers use SSL/TLS the encrypted connection uses the standard port __143__ or an alternative port such as __993__.

 | Command                       | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `a LOGIN username password`     | User's login.                                                               |
| `a LIST "" *`                   | Lists all directories.                                                      |
| `a CREATE "INBOX"`              | Creates a mailbox with a specified name.                                    |
| `a DELETE "INBOX"`              | Deletes a mailbox.                                                          |
| `a RENAME "ToRead" "Important"` | Renames a mailbox.                                                          |
| `a LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| `a SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed.          |
| `a UNSELECT INBOX`              | Exits the selected mailbox.                                                 |
| `a FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.                    |
| `a CLOSE`                       | Removes all messages with the Deleted flag set.                             |
| `a LOGOUT`                      | Closes the connection with the IMAP server.                                 |
| `a FETCH 1 FULL`                       | Fetches the entire message data for the first email.       |
| `a FETCH 1 (BODY[HEADER])`             | Fetches only the headers of the first email.               |
| `a FETCH 1 (BODY[TEXT])`               | Fetches only the body text of the first email.             |
| `a FETCH 1 (FLAGS)`                    | Retrieves the flags (e.g., \Seen, \Answered) for the first email. |
| `a FETCH 1 (ENVELOPE)`                 | Retrieves the envelope structure of the first email.       |
| `a FETCH 1 (INTERNALDATE RFC822.SIZE)` | Retrieves the internal date and size of the first email.   |
| `a FETCH 1 (UID)`                      | Retrieves the unique identifier for the first email.       |
| `a FETCH 1 (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY[TEXT])` | Fetches flags, internal date, size, envelope, and body text of the first email. |

### POP3 commands
| Command         | Description                                                      |
|-----------------|------------------------------------------------------------------|
| `USER username` | Identifies the user.                                             |
| `PASS password` | Authentication of the user using its password.                   |
| `STAT`          | Requests the number of saved emails from the server.             |
| `LIST`          | Requests from the server the number and size of all emails.      |
| `RETR id`       | Requests the server to deliver the requested email by ID.        |
| `DELE id`       | Requests the server to delete the requested email by ID.         |
| `CAPA`          | Requests the server to display the server capabilities.          |
| `RSET`          | Requests the server to reset the transmitted information.        |
| `QUIT`          | Closes the connection with the POP3 server.                      |

### Dangerous IMAP/POP3 Server Settings
| Setting                    | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `auth_debug`               | Enables all authentication debug logging.                                   |
| `auth_debug_passwords`     | Adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| `auth_verbose`             | Logs unsuccessful authentication attempts and their reasons.                |
| `auth_verbose_passwords`   | Passwords used for authentication are logged and can also be truncated.     |
| `auth_anonymous_username`  | Specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |

### IMAP/POP3 Footprinting
Ports 110 and 995 are used for POP3, and ports 143 and 993 are used for IMAP. The higher ports (993 and 995) use TLS/SSL

Nmap IMAP enumeration
```
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```
Curl IMAP Login
```
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v
```
OpenSSL TLS Encrypted Interaction POP3
```
openssl s_client -connect 10.129.14.128:pop3s
```
OpenSSL TLS Encrypted Interaction IMAP
```
openssl s_client -connect 10.129.14.128:imaps
```
# SNMP Enumeration
Simple Network Management Protocol (SNMP) was created to monitor network devices. In addition, this protocol can also be used to handle configuration tasks and change settings remotely. The current version is SNMPv3, which increases the security of SNMP in particular, but also the complexity of using this protocol.

SNMP also transmits control commands using agents over UDP port 161.SNMP also enables the use of so-called traps over UDP port 162. These are data packets sent from the SNMP server to the client without being explicitly requested. an SNMP __trap__ is sent to the client once a specific event occurs on the server-side.

### MIB
To ensure that SNMP access works across manufacturers and with different client-server combinations, the Management Information Base (MIB) was created. MIB contains all the SNMP objects (like data points) that a device can provide. Object Identifier (OID), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object (eg printer OID online status this shows if printer online or offline).

### SNMP Versions 
__SNMPv1__ has no built-in authentication does not support encryption. It supports the retrieval of information from network devices, allows for the configuration of devices, and provides traps.
__SNMPv2c__ is a version of SNMP used to manage network devices. It uses a password (community string) for security, but this password is sent without encryption, making it vulnerable to being intercepted and read by unauthorized parties.
__SNMPv3__ The security has been increased enormously for SNMPv3 by security features such as authentication using username and password and transmission encryption (via pre-shared key) of the data. 

### Dangerous Settings

| Settings                | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `rwuser noauth`         | Provides access to the full OID tree without authentication.                |
| `rwcommunity <community string> <IPv4 address>` | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6. |

### SNMP footprinting
Tools like snmpwalk, onesixtyone, and braa. Snmpwalk is used to query the OIDs with their information. Onesixtyone can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator.

__snmpwalk__
```
snmpwalk -v2c -c public 10.129.14.128
```
-c is the community string needed to query snmp. if community string is not known we can brute force using onesixtyone

___OneSixtyOne__
```
sudo apt install onesixtyone
onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128
```
Often, when certain community strings are bound to specific IP addresses, they are named with the hostname of the host, and sometimes even symbols are added to these names to make them more challenging to identify.

Once we know a community string, we can use it with braa to brute-force the individual OIDs and enumerate the information behind them.
__braa__
```
sudo apt install braa
braa <community string>@<IP>:.1.3.6.*   # Syntax
braa public@10.129.14.128:.1.3.6.*
```
# MYSQL Enumeration
MySQL is an open-source SQL relational database management system developed and supported by Oracle. MySQL works according to the client-server principle. MySQL is ideally suited for applications such as dynamic websites, where efficient syntax and high response speed are essential.
In a web hosting with MySQL database, this serves as a central instance in which content required by PHP scripts is stored. Among these are: ![image](https://github.com/user-attachments/assets/f3655193-4ca2-4a6e-b697-1615cfc4c156)

Sensitive data such as passwords can be stored in their plain-text form by MySQL; however, they are generally encrypted beforehand by the PHP scripts using secure methods such as One-Way-Encryption.

### Default Configuration File
```
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```
### Dangerous Settings
| Setting          | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| user             | Sets which user the MySQL service will run as.                              |
| password         | Sets the password for the MySQL user.                                       |
| admin_address    | The IP address on which to listen for TCP/IP connections on the administrative network interface. |
| debug            | This variable indicates the current debugging settings.                     |
| sql_warnings     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| secure_file_priv | This variable is used to limit the effect of data import and export operations. |

### Footprinting the Service
MySQL server runs on TCP port 3306.
```
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
Some results like passwords can be false negative. Command to interact with mysql server.
```
mysql -u root -h 10.129.14.132
```
```
mysql -u root -pP4SSw0rd -h 10.129.14.128
```
__Information Schema__: Think of this as a special database that holds information about other databases. It’s like a directory that tells you what tables, columns, and other objects exist in your databases. This information is standardized according to ANSI/ISO rules, making it consistent across different database systems.
__System Schema__: This is a more detailed catalog used by Microsoft SQL servers. It contains a lot more information than the Information Schema, including internal system details. It’s like an advanced directory with extra details that are specific to Microsoft SQL servers.

The above schemas are usually Databases in a server.
| Command                                      | Description                                                                 |
|----------------------------------------------|-----------------------------------------------------------------------------|
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. There should not be a space between the '-p' flag, and the password. |
| `show databases;`                            | Show all databases.                                                         |
| `use <database>;`                            | Select one of the existing databases.                                       |
| `show tables;`                               | Show all available tables in the selected database.                         |
| `show columns from <table>;`                 | Show all columns in the selected database.                                  |
| `select * from <table>;`                     | Show everything in the desired table.                                       |
| `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table.                              |

# MSSQL Enumeration

Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system. SQL Server Management Studio (SSMS) comes as a feature that can be installed with the MSSQL install package or can be downloaded & installed separately. It is commonly installed on the server for initial configuration and long-term management of databases by admins. It is installed not only on the MSSQL server but on other desktops that need to manage the server.

MSSQL clients ![image](https://github.com/user-attachments/assets/c1f153a7-0a37-4ba2-85d0-aa6ef0ce4805)

### Locate MSSQLclient
```
locate mssqlclient
```

| Default System Database | Description                                                                                           |
|-------------------------|-------------------------------------------------------------------------------------------------------|
| `master`                | Tracks all system information for an SQL server instance                                              |
| `model`                 | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb`                  | The SQL Server Agent uses this database to schedule jobs & alerts                                     |
| `tempdb`                | Stores temporary objects                                                                              |
| `resource`              | Read-only database containing system objects included with SQL server                                 |

### Default configuration

Once admin installs the mssql server. To make it network accessible the service will run NT SERVICE\MSSQLSERVER. Connecting from the client-side is possible through Windows Authentication, and by default, encryption is not enforced when attempting to connect.

Authentication being set to Windows Authentication means that the underlying Windows OS will process the login request and use either the local SAM database or the domain controller (hosting Active Directory) before allowing connectivity to the database management system.

### Dangerous Settings
1) MSSQL clients not using encryption to connect to the MSSQL server

2) The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates

3) The use of named pipes

4) Weak & default sa credentials. Admins may forget to disable this account

### Footprinting MSSQL

__Nmap__
```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

Metasploit to run an auxiliary scanner called __mssql_ping__ that will scan the MSSQL service and provide helpful information

__Mssqlclient.py__
```
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
select name from sys.databases
```
# Oracle TNS Enumeration

The Oracle Transparent Network Substrate (TNS) server is a communication protocol that facilitates communication between Oracle databases and applications over networks.
its built-in encryption mechanism ensures the security of data transmitted, making it an ideal solution for enterprise environments where data security is paramount (IPv6 and SSL/TLS encryption).
It enables encryption between client and server communication through an additional layer of security over the TCP/IP protocol layer. 

TNS listens on port __TCP/1511__ Oracle TNS can be remotely managed in Oracle 8i/9i but not in Oracle 10g/11g. listener accepts only authorized hosts using combination of hostnames,IPs, username and passwords. The configuration files for Oracle TNS are called tnsnames.ora and listener.ora and are typically located in the $ORACLE_HOME/network/admin directory.

Oracle TNS: Used for communication between Oracle services.
Default Passwords:
Oracle 9: Default password “CHANGE_ON_INSTALL”.
Oracle 10: No default password set.
Oracle DBSNMP: Default password “dbsnmp”.
Security Risks:
Finger Service: Can expose user information (e.g., home directories), posing a security risk when used with Oracle services.

The client-side Oracle Net Services software uses the __tnsnames.ora__ file to resolve service names to network addresses, while the listener process uses the __listener.ora__ file to determine the services it should listen to and the behavior of the listener.

PL/SQL Exclusion List (PlsqlExclusionList). It is a user-created text file that needs to be placed in the $ORACLE_HOME/sqldeveloper directory, and it contains the names of PL/SQL packages or types that should be excluded from execution.

| Setting            | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| DESCRIPTION        | A descriptor that provides a name for the database and its connection type. |
| ADDRESS            | The network address of the database, which includes the hostname and port number. |
| PROTOCOL           | The network protocol used for communication with the server.                |
| PORT               | The port number used for communication with the server.                     |
| CONNECT_DATA       | Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier. |
| INSTANCE_NAME      | The name of the database instance the client wants to connect.              |
| SERVICE_NAME       | The name of the service that the client wants to connect to.                |
| SERVER             | The type of server used for the database connection, such as dedicated or shared. |
| USER               | The username used to authenticate with the database server.                 |
| PASSWORD           | The password used to authenticate with the database server.                 |
| SECURITY           | The type of security for the connection.                                    |
| VALIDATE_CERT      | Whether to validate the certificate using SSL/TTLS.                         |
| SSL_VERSION        | The version of SSL/TLS to use for the connection.                           |
| CONNECT_TIMEOUT    | The time limit in seconds for the client to establish a connection to the database. |
| RECEIVE_TIMEOUT    | The time limit in seconds for the client to receive a response from the database. |
| SEND_TIMEOUT       | The time limit in seconds for the client to send a request to the database. |
| SQLNET.EXPIRE_TIME | The time limit in seconds for the client to detect a connection has failed. |
| TRACE_LEVEL        | The level of tracing for the database connection.                           |
| TRACE_DIRECTORY    | The directory where the trace files are stored.                             |
| TRACE_FILE_NAME    | The name of the trace file.                                                 |
| LOG_FILE           | The file where the log information is stored.                               |

### Oracle-tools-setup.sh
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

### ODAT 

ODAT is tool to enumarate and exploit vulnerabilities in oracle databases.
```
./odat.py -h
```

ODAT all scripts option
```
./odat.py all -s 10.129.204.235
```

Oracle TNS Nmap
```
sudo nmap -p1521 -sV 10.129.204.235 --open
```
In Oracle RDBMS, a System Identifier (SID) is a unique name that identifies a particular database instance.client connects to an Oracle database, it specifies the database's SID along with its connection string. These SID's are in __tsnames.ora__ usually.

### Nmap SID Bruteforce 
```
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
```
### SQLplus login
```
sqlplus scott/tiger@10.129.204.235/XE #scott is user and tiger password from odat all scan
```
If you come across the following error sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory, please execute
```
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```
### Oracle RDBMS Interaction
```
select table_name from all_tables;
```
```
select * from user_role_privs;
```

If user does not privledges we can use the same account to try to login as the System Database Admin (sysdba), giving us higher privileges. This possible if admin has granted or account is of admin.

```
sqlplus scott/tiger@10.129.204.235/XE as sysdba # Trying to login scott as sysdba
select * from user_role_privs; # To see privledges 
```

### Oracle RDBMS Extract Password Hashes

```
 select name, password from sys.user$;
```
### Oracle RDBMSFile Upload
Another option is to upload a web shell to the target. However, this requires the server to run a web server, and we need to know the exact location of the root directory for the webserver. 

| OS      | Path                |
|---------|---------------------|
| Linux   | /var/www/html       |
| Windows | C:\inetpub\wwwroot  |

Try uploading using normal text file before uploading shell to test the IPS/IDS.
```
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```
Curl the uploaded file
```
curl -X GET http://10.129.204.235/testing.txt
```

# IPMI Enumeration 
Intelligent Platform Management Interface (IPMI) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. IPMI can manage system and monitor even if system is OFF.

IPMI can monitor a range of different things such as system temperature, voltage, fan status, and power supplies.
IPMI needs several key components:

1) Baseboard Management Controller (BMC): Think of this as the brain of IPMI. It’s a small computer within the main computer that handles the management tasks.
2) Intelligent Chassis Management Bus (ICMB): This is like a communication highway that allows different computer cases (chassis) to talk to each other.
3) Intelligent Platform Management Bus (IPMB): This extends the BMC’s reach, allowing it to manage more parts of the system.
4) IPMI Memory: This is where important information is stored, like system logs and data repositories.
5) Communications Interfaces: These are the various ways the BMC can communicate, including local system interfaces, serial and LAN interfaces, and other buses like ICMB and PCI Management Bus.

IPMI runs on port __UDP/623__. Baseboard Management Controllers (BMCs) are the systems that use IPMI. They usually run ARM processor and use linux. BMC are usually exposed using a web-based management console for remote access using Telnet or ssh  and the port.

### NMAP IPMI Scan
```
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

### Metasploit IPMI Version Scan 
```
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options
```
### Default BMC Username/Password 
| Product          | Username     | Password                                                |
|------------------|--------------|---------------------------------------------------------|
| Dell iDRAC       | root         | calvin                                                  |
| HP iLO           | Administrator| randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI  | ADMIN        | ADMIN                                                   |

### Dangerous Settings
flaw in the RAKP protocol in IPMI 2.0. During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place. This can be used to gain hash for any valid user on BMC. These hashes can be cracked offline using hashcat.

In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u which tries all combinations of upper case letters and numbers for an eight-character password.

Metasploit Dump hashes
```
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options
```
Crack Hash
```
hashcat -m 7300 -w 3 -O "93c887ae8200000052f17511d0fd3b9a08350b045e118a2cd0c311777576080bc13a5581d522cdb5a123456789abcdefa123456789abcdef140561646d696e:3541221bac8d7e76f34e45697aed40edfbe87fd8" /usr/share/wordlists/rockyou.txt
```
