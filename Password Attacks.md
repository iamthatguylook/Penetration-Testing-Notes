# Credential Storage in Linux
- **Credential Storage**: Authentication mechanisms store credentials locally or in databases. Web apps are vulnerable to SQL injections, potentially exposing plaintext data.
- **Common Password Wordlists**: Example - `rockyou.txt`, created after the RockYou breach (32M accounts stored in plaintext).

### Linux Credential Storage
- **Password Storage**: Located in `/etc/shadow`, part of Linux user management.
- **Password Format**: Usually stored as hashes.

### `/etc/shadow` File Structure
- **File Location**: `/etc/shadow`
- **Example Entry**:

![image](https://github.com/user-attachments/assets/a94bf53d-a0ed-44a6-bede-5089a6f1cbd1)


### Password Encryption Format
- **General Format**: `$<id>$<salt>$<hashed password>`
- Example: `$ y	$ j9T	$ 3QSBB6CbHEu...SNIP...f8Ms`

### Cryptographic Hash Algorithms
| ID    | Algorithm         |
|-------|-------------------|
| $1$   | MD5               |
| $2a$  | Blowfish          |
| $5$   | SHA-256           |
| $6$   | SHA-512           |
| $sha1$| SHA1crypt         |
| $y$   | Yescrypt          |
| $gy$  | Gost-yescrypt     |
| $7$   | Scrypt            |

### Additional User Management Files
1. **`/etc/passwd`**
   ![image](https://github.com/user-attachments/assets/31fb511b-1a52-4bc2-b700-b7e1e37943da)

 - Previously stored encrypted passwords; now only accessible by root.
 - **Format**: `<username>:x:<uid>:<gid>:<comment>:<home directory>:<cmd after login>`
 - The `x` indicates the password is in `/etc/shadow`.

2. **`/etc/group`**
 - Manages group information.


### Security Note
- **Permissions Matter**: Incorrect `/etc/shadow` file permissions can lead to root user login vulnerabilities without a password.

## Windows Authentication Process

- **Windows Authentication** involves complex modules for logon, retrieval, and verification (e.g., Kerberos).
- **Local Security Authority (LSA)**: Authenticates users, maintains local security info, manages security IDs (SIDs), and checks access permissions.
- **Domain Controllers**: Store security policies and accounts in Active Directory for centralized management.

### Key Components
1. **Winlogon**
   - Manages security-related user interactions (login, password changes, workstation locking).
   - Uses **Credential Providers** (COM objects in DLLs) to obtain login details.
   - **LogonUI**: Displays login interface and gathers credentials.

2. **LSASS (Local Security Authority Subsystem Service)**
   - Located at `%SystemRoot%\System32\Lsass.exe`.
   - Manages local security policies, user authentication, and security audit logs.
   - **Authentication Packages**:
     | Package       | Description                                            |
     |---------------|--------------------------------------------------------|
     | `Lsasrv.dll`  | Enforces security policies; manages security packages. |
     | `Msv1_0.dll`  | Handles non-domain logins.                             |
     | `Samsrv.dll`  | Manages local security accounts.                       |
     | `Kerberos.dll`| Handles Kerberos-based authentication.                 |
     | `Netlogon.dll`| Network-based logon service.                           |
     | `Ntdsa.dll`   | Manages Windows registry records.                      |

### SAM Database
- **Location**: `%SystemRoot%\system32\config\SAM`, mounted at `HKLM/SAM`.
- **Role**: Stores user passwords in hash format (LM/NTLM). Requires SYSTEM permissions for access.
- **Workgroup vs. Domain**:
  - **Workgroup**: SAM handles credentials locally.
  - **Domain**: Domain Controller validates credentials using the Active Directory database (`ntds.dit`).

### NTDS.dit
- **Active Directory Database** stored at `%SystemRoot%\ntds.dit`.
- **Contents**: User accounts (username & password hash), group accounts, computer accounts, and group policy objects.
- **Synchronization**: NTDS.dit is synced across Domain Controllers (excluding Read-Only Domain Controllers).

### Credential Manager
- **Role**: Saves credentials for network resources and websites, encrypted in the **Credential Locker**.
- **Storage Location**: 
PS C:\Users[Username]\AppData\Local\Microsoft[Vault/Credentials]\

- **Decryption Methods**: Various tools and techniques can decrypt stored credentials.

### Security Features
- **SYSKEY (Windows NT 4.0)**: Partially encrypts the SAM database to protect password hashes from offline attacks.

### NTDS (Network Directory Services)
- **Domain Environment**: Common in networks where Windows systems are joined to a domain.
- **Logon Requests**: Sent to Domain Controllers within the same Active Directory forest.
- **NTDS.dit File**: Stores various Active Directory data, such as:
- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

# John the Ripper (JTR)
- **JTR** is a popular open-source tool for testing password strength and cracking encrypted passwords using brute force or dictionary attacks.
- Initially developed for UNIX-based systems (1996), it is widely used in the security field.
- The "Jumbo" variant includes optimizations, multilingual wordlists, and support for 64-bit systems.

## Supported Encryption Technologies
- **UNIX crypt(3)**: Traditional UNIX encryption with a 56-bit key.
- **DES-based**: Uses the Data Encryption Standard.
- **Blowfish-based**: 448-bit key encryption.
- **SHA-crypt hashes**: Commonly used in modern Linux distributions.
- **Windows LM**: Uses a 56-bit key for encryption.
- **And many more**: Supports a wide range of encryption formats.

## Attack Methods
1. **Dictionary Attacks**:
   - Uses a pre-generated list of words to compare against hashed passwords.
   - Common and effective but requires comprehensive wordlists.
2. **Brute Force Attacks**:
   - Attempts every possible combination of characters.
   - Time-consuming, especially for long or complex passwords.
3. **Rainbow Table Attacks**:
   - Uses precomputed hash-password pairs for quick lookup.
   - Limited by the size of the rainbow table.

## Cracking Modes
1. **Single Crack Mode**:
   - Uses built-in wordlist or user-specified rules.
   - Basic but less efficient for complex passwords.
   - Command example:
   - ```
     john --format=<hash_type> <hash_file>
     ```
     ## Cracking with John
   - Supports various hash formats, e.g.,
  ```
  john --format=sha256 hashes_to_crack.txt`.
  ```
   - Outputs cracked passwords to "john.pot" in the user's home directory.
   - Progress can be viewed with `john --show`.
![image](https://github.com/user-attachments/assets/5a5c0ab1-6829-4b8c-8935-6f87483f775c)

2. **Wordlist Mode**:
   - Cracks passwords using one or more wordlists.
   - Allows applying mangling rules to modify words in the list.
   - Command example:
   - ```
     john --wordlist=<wordlist_file> --rules <hash_file>
     ```



 3. Incremental Mode in John
   - **Command:** `john --incremental <hash_file>`
     - Reads the hashes from the specified file and generates all possible character combinations, incrementing the length with each iteration.
     - **Resource-Intensive:** Takes a long time to complete, depending on password complexity and system performance.
     - **Character Set:** Default is `a-zA-Z0-9`. For complex passwords with special characters, a custom character set is needed.

### Cracking Files with John
It is also possible to crack even password-protected or encrypted files with John. We use additional tools that process the given files and produce hashes that John can work with. It automatically detects the formats and tries to crack them.

```

pdf2john server_doc.pdf > server_doc.hash
 john server_doc.hash
```
```
 john --wordlist=<wordlist.txt> server_doc.hash
```
![image](https://github.com/user-attachments/assets/58c7507c-0f88-4090-baf8-7f87df75cc81)

locate more tools

```
locate *2john*
```
# Network Services

- During penetration tests, networks have various services to manage, edit, or create content, hosted with specific permissions.
- Common services include:
  - **FTP** - **SMB**  - **NFS** - **IMAP/POP3** - **SSH** - **MySQL/MSSQL** - **RDP** - **WinRM** - **VNC** - **Telnet**- **SMTP**- **LDAP**

### Managing Windows Server
- To manage a Windows server remotely, use services like:
  - **RDP** (Remote Desktop Protocol)
  - **WinRM** (Windows Remote Management)
  - **SSH** (less common on Windows)

- All services typically require authentication (username and password), though they can be configured for key-based access.

### WinRM
- **Definition:** Windows Remote Management (WinRM) is the Microsoft implementation of the WS-Management protocol.
- **Protocol Type:** Based on XML web services using SOAP for remote management.
- **Communication:** Interfaces with WBEM and WMI, can invoke DCOM.
- **Configuration:** Must be manually activated on Windows 10; depends on security settings in the environment.
- **Ports Used:** 
  - **TCP 5985** (HTTP)
  - **TCP 5986** (HTTPS)

### CrackMapExec
- **Purpose:** Tool for password attacks, also supports SMB, LDAP, MSSQL, etc.
- **Installation Command:**  
  ```bash
  sudo apt-get -y install crackmapexec
  ```
**CrackMapExec Menu Options**
```
crackmapexec -h
```

**CrackMapExec Protocol-Specific Help**

```
crackmapexec smb -h
```

**CrackMapExec Usage**
```
crackmapexec winrm 10.129.42.197 -u user.list -p password.list`
```
![image](https://github.com/user-attachments/assets/970fcdc5-c6e6-4b6a-b643-3f73d912fa8f)
The appearance of (Pwn3d!) is the sign that we can most likely execute system commands if we log in with the brute-forced user. 

Communicate with the WinRM service is Evil-WinRM

### Evil-WinRM

**Installing Evil-WinRM**

```
sudo gem install evil-winrm
```
**Evil-WinRM Usage**

```
 evil-winrm -i 10.129.42.197 -u user -p password
```

### SSH (Secure Shell)
- **Definition:** A secure method to connect to remote hosts for executing commands or transferring files.
- **Default Port:** TCP port **22**.
- **Encryption Methods:**
  - **Symmetric Encryption:** Same key for encryption and decryption. Requires a key exchange (e.g., Diffie-Hellman). Common ciphers include AES, Blowfish, and 3DES.
  - **Asymmetric Encryption:** Uses a private key (kept secret) and a public key. The server uses the public key for authentication; the client decrypts messages with the private key.
  - **Hashing:** Converts transmitted data into a unique value to confirm authenticity.

### Hydra for SSH
- **Command to brute-force SSH:**
  ```bash
  hydra -L user.list -P password.list ssh://10.129.42.197
  ```
Login to SSH

```
 ssh user@10.129.42.197
```
### RDP
- Definition: Microsoft's protocol for remote access to Windows systems.
- Default Port: TCP port 3389.
- Features:
   Allows remote access to Windows hosts.
   Supports audio, keyboard, mouse input, and document printing.
   Application layer protocol using TCP and UDP.

**Hydra for RDP**
```
hydra -L user.list -P password.list rdp://10.129.42.197
```

**XFreeRdp**

```
xfreerdp /v:<target-IP> /u:<username> /p:<password>
```
### Server Message Block (SMB)

- **Purpose**: Protocol for transferring data between client and server in local area networks.
- **Uses**:
  - File and directory sharing
  - Printing services in Windows networks
- **Comparison**: Similar to NFS for Unix/Linux for local network drives.
- **Also Known As**: Common Internet File System (CIFS).
- **Compatibility**: Enables remote connections across platforms (Windows, Linux, macOS).
- **Open Source Implementation**: Samba.
- **Brute Forcing Tool**: Hydra can be used to attempt different usernames and passwords with SMB.

**Hydra - SMB**

```
hydra -L user.list -P password.list smb://10.129.42.197
```
you may get an error rThis is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile hydra or use another very powerful tool, the Metasploit framework.

**Metasploit Framework**

```
msfconsole -q
use auxiliary/scanner/smb/smb_login
```
then set the wordlist and for both user and pass to bruteforce.

Now we can use CrackMapExec again to view the available shares and what privileges we have for them.

**CrackMapExec**

```
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

use smbclient to communicate

**Smbclient**
```
smbclient -U user \\\\10.129.42.197\\SHARENAME
```
# Password Mutations

- **Purpose**: Enhance security by enforcing password complexity through policies.
- **Common Password Policies**:
  - Minimum length: 8 characters
  - Must include: 
    - Capital letters
    - Special characters
    - Numbers

- **Weak Password Patterns**:
  - Users often create passwords related to their interests or company names.
  - Common additions for weak passwords:
    - First letter uppercase: `Password`
    - Adding numbers: `Password123`
    - Adding year: `Password2022`
    - Adding month: `Password02`
    - Last character as exclamation mark: `Password2022!`
    - Adding special characters: `P@ssw0rd2022!`

- **Password Length Statistics**: 
  - Most passwords are not longer than 10 characters.
  
- **Example of Password Creation**:
  - Combining a single word with the current year and a special character can meet complexity requirements (e.g., `January2022!`).

### Password List Example

We can use a very powerful tool called Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists. 

![image](https://github.com/user-attachments/assets/85190865-3329-4241-8228-d3c84b6ad42c)

![image](https://github.com/user-attachments/assets/d29d9ebc-bc78-4274-a223-8351ae294bcd)

Each rule is written on a new line which determines how the word should be mutated.

### Hashcat Rule File
store the below into a file eg. custom.rule
```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

Hashcat will apply the rules of custom.rule for each word in password.list and store the mutated version in our mut_password.list 
### Generating Rule-based Wordlist
```
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
cat mut_password.list
```
Hashcat and John come with pre-built rule lists that we can use for our password generating and cracking purposes. One of the most used rules is best64.rule, which can often lead to good results. 
Here’s a condensed version of the text without bullet points:

Password cracking is primarily a guessing game, but it can become more effective with targeted guessing. By understanding the password policy and considering factors like the company name, geographical region, and industry-specific terms, one can tailor the approach to better align with users' likely choices. Exceptions occur when passwords are leaked, providing direct insight into potential passwords.

**Hashcat Existing Rules**

```
 ls /usr/share/hashcat/rules/
```
### Generating Wordlists Using CeWL
We can now use another tool called CeWL to scan potential words from the company's website and save them in a separate list. specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).

```
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
wc -l inlane.wordlist
```
# Password Reuse / Default Passwords

## Default Credentials and Credential Stuffing

- **Common Issues**:
  - Users and administrators often leave default credentials in place, forgetting to change them after installation.
  - Easy-to-remember passwords are frequently reused, especially in large infrastructures with many interfaces.

- **Credential Stuffing**:
  - Involves using known default credentials to access services.
  - Simpler than brute-forcing as it uses composite usernames and passwords from known lists.

- **Default Credential Sources**:
  - Common databases like the [DefaultCreds-Cheat-Sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) list known default credentials for various products.

Default credentials can also be found in the product documentation, as they contain the steps necessary to set up the service successfully. Some devices/applications require the user to set up a password at install, but others use a default, weak password. Attacking those services with the default or obtained credentials is called Credential Stuffing.  we can create a new list that separates these composite credentials with a colon (username:password). In addition, we can select the passwords and mutate them by our rules to increase the probability of hits.

- **Hydra Usage for Credential Stuffing**:
- Create a list of composite credentials (username:password).
- Use the following Hydra syntax to perform credential stuffing:
  ```bash
  hydra -C <user_pass.list> <protocol>://<IP>
  ```
- Example for SSH:
  ```bash
  hydra -C user_pass.list ssh://10.129.42.197
  ```

- **Role of OSINT**:
- Helps understand company structure and infrastructure for better password and username combinations.
- Useful for identifying hardcoded credentials in applications via Google searches.

**Google Search - Default Credentials**
![image](https://github.com/user-attachments/assets/f862824f-cf47-4c33-a32a-692371b1c6b5)

In addition to application default credentials, there are [lists](https://www.softwaretestinghelp.com/default-router-username-and-password-list/) available specifically for routers. However, it's less common for router default credentials to remain unchanged since administrators usually prioritize securing these central network interfaces.







