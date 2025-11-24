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

