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
