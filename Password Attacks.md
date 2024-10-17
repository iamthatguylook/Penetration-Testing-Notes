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

