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
